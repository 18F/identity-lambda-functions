# frozen_string_literal: true

require 'logger'
require 'aws-sdk-dynamodb'
require 'aws-sdk-sns'
require 'aws-sdk-sqs'

module IdentityKMSMonitor

  # Class for inputting CloudTrail events into DynamoDB
  class CloudTrailToDynamoHandler < Functions::AbstractLambdaHandler

    attr_reader :dynamo

    Functions.register_handler(self, 'cloudtrail-to-dynamo')

    def initialize(log_level: Logger::INFO, dry_run: true, dynamo: nil,
                   sns: nil, sqs: nil)
      super(log_level: log_level, dry_run: dry_run)

      begin
        @dynamo = dynamo || Aws::DynamoDB::Client.new
        @sns = sns || Aws::SNS::Client.new
        @sqs = sqs || Aws::SQS::Client.new
      rescue StandardError
        log.error('Failed to create DynamoDB client. Do you have AWS creds?')
        raise
      end
    end

    # This is the main CLI handler function
    #
    def cli_main(_args)
      log.info('Reading JSON event from STDIN...')
      event = JSON.parse(STDIN.read)
      process_event(event)
    end

    # This is the main lambda handler function
    #
    # @param [Hash, String] event The event received from AWS Lambda
    # @param context The context received from AWS Lambda
    #
    def lambda_main(event:, context:)
      _ = context
      process_event(event)
    end

    # @param [Hash] event
    def process_event(event)
      process_records(event.fetch('Records'))
    end

    # @param [Array<Hash>] records
    def process_records(records)
      records.each do |record|
        process_record(record)
      end
    end

    # @param [Hash] record
    def process_record(record)
      body = JSON.parse(record.fetch('body'))
      log.info("record body: #{body}")

      ctevent = CloudTrailEvent.new
      timestamp = Time.parse(body.fetch('detail').fetch('eventTime')).utc
      ctevent.timestamp = timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
      request_parameters = body.fetch('detail').fetch('requestParameters')
      ctevent.uuid = request_parameters.fetch(
        'encryptionContext').fetch('user_uuid')
      ctevent.context = request_parameters.fetch(
        'encryptionContext').fetch('context')

      dbrecord = get_db_record(ctevent.get_key, ctevent.timestamp)

      # calculate retry count will not be used if we found the record in table
      retrycount = get_attribute_value_int(record, 'RetryCount')
      retrycount += 1

      if dbrecord
        # found the record in table, update and mark correlated
        # generate event
        log.info('Matching CloudWatch event found. Marking correlated in ' +
                 'database and notifying SNS.')
        insert_into_db(ctevent.get_key, ctevent.timestamp, body,
                       dbrecord.fetch('CWData'), 1)
        log_event_sns(ctevent, body.fetch('id'), true)
      elsif retrycount <= 5
        # put message back on queue
        log.info('No matching CloudWatch event found. Requeuing this event.')
        delay = calculate_delay(retrycount)
        put_message_queue(body, delay, retrycount)
      else
        # all retries exhausted, put record in table uncorrelated
        log.info('No matching CloudWatch event found and retries exhausted. ' +
                 'Marking this event uncorrelated in the database and ' +
                 'notifying SNS.')
        insert_into_db(ctevent.get_key, ctevent.timestamp, body, '', 0)
        # generate SNS event to notify of the issue
        log_event_sns(ctevent, body.fetch('id'), false)
      end
    end

    def log_event_sns(ctevent, cloudtrail_id, correlated)
      logentry = LogEntry.new
      logentry.uuid = ctevent.uuid
      logentry.operation = 'decrypt'
      logentry.context = ctevent.context
      logentry.timestamp = ctevent.timestamp
      logentry.cloudtrail_id = cloudtrail_id
      logentry.correlated = correlated
      logentry.late_correlation = false

      begin
        @sns.publish(
          topic_arn: ENV.fetch('SNS_EVENT_TOPIC_ARN'),
          message: logentry.to_json
                     )
      rescue Aws::DynamoDB::Errors::ServiceError => error
        log.error "Failure publishing to SNS: #{error.message}"
        raise
      end
    end

    def put_message_queue(message_body, message_delay, message_retrycount)
      bodystring = message_body.to_json
      @sqs.send_message(
        queue_url: ENV.fetch('CT_QUEUE_URL'),
        message_body: bodystring,
        delay_seconds: message_delay,
        message_attributes: {
          'RetryCount' => {
            string_value: message_retrycount.to_s,
            data_type: 'Number',
          },
        }
                        )
    rescue Aws::SQS::Errors::ServiceError => error
      log.error "Failure publishing to SQS: #{error.message}"
      raise
    end

    def get_attribute_value_int(record, attribute_key)
      attributes = record.fetch('messageAttributes', nil)
      log.info("message attributes: #{attributes}")
      if attributes
        attribute = attributes.fetch(attribute_key, nil)
      end
      if attribute
        attribute_value = attribute.fetch('stringValue', '0')
      end
      if !attributes || !attribute
        attribute_value = '0'
      end
      Integer(attribute_value)
    end

    def calculate_delay(counter)
      [900, (counter**2) * 30].min
    end

    def get_db_record(uuid, timestamp)
      begin
        result = dynamo.get_item(
          table_name: ENV.fetch('DDB_TABLE'),
          key: { 'UUID' => uuid,
                 'Timestamp' => timestamp, },
          consistent_read: true
          )
      rescue Aws::DynamoDB::Errors::ServiceError => error
        log.error "Failure looking up event: #{error.message}"
        raise
      end
      log.info "Database query result: #{result}"
      result.item
    end

    def insert_into_db(uuid, timestamp, ctdata, cwdata, _correlated)
      table_name = ENV.fetch('DDB_TABLE')
      ttl = Time.now.utc + Integer(ENV.fetch('RETENTION_DAYS'))
      ttlstring = ttl.strftime('%Y-%m-%dT%H:%M:%SZ')
      item = {
        'UUID' => uuid,
        'Timestamp' => timestamp,
        'Correlated' => '1',
        'CTData' => ctdata,
        'TimeToExist' => ttlstring,
      }
      unless cwdata.empty?
        item['CWData'] = cwdata
      end

      params = {
        table_name: table_name,
        item: item,
      }

      begin
        log.info "Writing event with params: #{params}"
        dynamo.put_item(params)
      rescue Aws::DynamoDB::Errors::ServiceError => error
        log.info "Failure adding event: #{error.message}"
      end
    end

  end

  # KMS events reported by CloudTrail.
  class CloudTrailEvent
    attr_accessor :context, :uuid, :timestamp

    def get_key()
      @uuid + '-' + @context
    end

    def to_h(_options = {})
      {
        uuid: @uuid,
        timestamp: @timestamp,
        context: @context,
      }
    end

    def to_json(*options)
      to_h(*options).to_json(*options)
    end
  end

  # Events we write to SNS
  class LogEntry

    attr_accessor :context, :operation, :uuid, :timestamp, :cloudtrail_id,
                  :late_correlation, :correlated

    def to_h(_options = {})
      {
        uuid: @uuid,
        operation: @operation,
        context: @context,
        timestamp: @timestamp,
        cloudtrail_id: @cloudtrail_id,
        correlated: @correlated,
        late_correlation: @late_correlation,
      }
    end

    def to_json(*options)
      to_h(*options).to_json(*options)
    end
  end

end
