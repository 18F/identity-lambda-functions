# frozen_string_literal: true

require 'logger'
require 'aws-sdk-dynamodb'

module IdentityKMSMonitor

  # Class for inputting CloudTrail events into DynamoDB
  class CloudTrailToDynamoHandler < Functions::AbstractLambdaHandler

    attr_reader :dynamo

    Functions.register_handler(self, 'cloudtrail-to-dynamo')

    def initialize(log_level: Logger::INFO, dry_run: true, dynamo: nil)
      super(log_level: log_level, dry_run: dry_run)

      begin
        @dynamo = dynamo || Aws::DynamoDB::Client.new
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

      ctevent = CloudTrailEvent.new
      timestamp = Time.parse(body.fetch('detail').fetch('eventTime')).utc
      ctevent.timestamp = timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
      request_parameters = body.fetch('detail').fetch('requestParameters')
      ctevent.uuid = request_parameters.fetch(
        'encryptionContext').fetch('user_uuid')
      ctevent.context = request_parameters.fetch(
        'encryptionContext').fetch('context')

      # get matching record
      apprecord = get_app_record(ctevent.get_key, ctevent.timestamp)
      log.info "apprecord result: #{apprecord.to_h}"

      if apprecord&.key?('CWData')
        insert_into_db(ctevent.get_key, ctevent.timestamp, body,
                       apprecord['CWData'])
      else
        log.error 'No CloudWatch data found for this event.'
      end
    end

    def get_app_record(uuid, timestamp)
      begin
        result = dynamo.get_item(
          table_name: ENV.fetch('DDB_TABLE'),
          key: { 'UUID' => uuid,
                 'Timestamp' => timestamp },
          consistent_read: false
                                 )
      rescue Aws::DynamoDB::Errors::ServiceError => error
        log.error "Failure looking up event: #{error.message}"
        raise
      end
      log.info "Database query result: #{result}"
      result.item
    end

    def insert_into_db(uuid, timestamp, ctdata, cwdata)
      table_name = ENV.fetch('DDB_TABLE')
      ttl = Time.now.utc + 365
      ttlstring = ttl.strftime('%Y-%m-%dT%H:%M:%SZ')
      item = {
        'UUID' => uuid,
        'Timestamp' => timestamp,
        'Correlated' => '1',
        'CTData' => ctdata,
        'CWData' => cwdata,
        'TimeToExist' => ttlstring,
      }

      params = {
        table_name: table_name,
        item: item,
      }

      begin
        dynamo.put_item(params)
        log.info "Added event for user_uuid: #{uuid}"
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

end
