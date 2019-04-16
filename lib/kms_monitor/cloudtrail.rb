# frozen_string_literal: true

require 'logger'
require 'aws-sdk-dynamodb'

module IdentityKMSMonitor

  # Class for inputting CloudTrail events into DynamoDB
  class CloudTrailToDynamoHandler

    attr_reader :dynamo

    def initialize(log_level: Logger::INFO, dry_run: true, dynamo: nil)
      log.level = log_level
      log.debug("Initializing, dry_run: #{dry_run.inspect}")

      @dry_run = dry_run

      begin
        @dynamo = dynamo || Aws::DynamoDB::Client.new
      rescue StandardError
        log.error('Failed to create DynamoDB client. Do you have AWS creds?')
        raise
      end
    end

    # @return [String]
    def main(_args)
      event = JSON.parse(STDIN.read)
      inner_process(event)
    end

    # @lambda_event and @lambda_context are instance variables we inherit from
    # the parent
    def process_event
      records = @lambda_event['Records']
      process_records(records)
    end

    def inner_process(event)
      @lambda_event = event
      process_event
    end

    def process_records(records)
      records.each do |record|
        process_record(record)
      end
    end

    def process_record(record)
      body = JSON.parse(record['body'])

      ctevent = CloudTrailEvent.new
      timestamp = Time.parse(body['detail']['eventTime']).utc
      ctevent.timestamp = timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
      request_parameters = body['detail']['requestParameters']
      ctevent.uuid = request_parameters['encryptionContext']['user_uuid']
      ctevent.context = request_parameters['encryptionContext']['context']

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
          table_name: ENV['DDB_TABLE'],
          key: { 'UUID' => uuid,
                 'Timestamp' => timestamp },
          consistent_read: false
                                 )
      rescue Aws::DynamoDB::Errors::ServiceError => error
        log.info "Failure adding event: #{error.message}"
      end
      log.info "Database query result: #{result}"
      result.item
    end

    def insert_into_db(uuid, timestamp, ctdata, cwdata)
      table_name = ENV['DDB_TABLE']
      ttl = Time.now.utc + 365
      ttlstring = ttl.strftime('%Y-%m-%dT%H:%M:%SZ')
      item = {
        'UUID' => uuid,
        'Timestamp' => timestamp,
        'Correlated' => '1',
        'CTData' => ctdata,
        'CWData' => cwdata,
        'TimeToExist' => ttlstring
      }

      params = {
        table_name: table_name,
        item: item
      }

      begin
        dynamo.put_item(params)
        log.info "Added event for user_uuid: #{uuid}"
      rescue Aws::DynamoDB::Errors::ServiceError => error
        log.info "Failure adding event: #{error.message}"
      end
    end

    def log
      @log ||= Logger.new(STDERR).tap { |l|
        l.progname = self.class.name
      }
    end

  end

  # KMS events reported by CloudTrail.
  class CloudTrailEvent
    attr_writer :uuid
    attr_writer :timestamp
    attr_writer :context
    attr_reader :uuid

    attr_reader :timestamp

    attr_reader :context

    def get_key()
      @uuid + '-' + @context
    end

    def to_h(_options = {})
      {
        action: @action,
        uuid: @uuid,
        timestamp: @timestamp,
        context: @context
      }
    end

    def to_json(*options)
      to_h(*options).to_json(*options)
    end
  end

end
