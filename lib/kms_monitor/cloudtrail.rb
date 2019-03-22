# frozen_string_literal: true

require 'logger'
require 'aws-sdk-dynamodb'

module IdentityKMSMonitor

  # Class for inputting CloudTrail events into DynamoDB
  class AwsCloudTrailEventWriter

    attr_reader :dynamo

    def initialize(log_level: Logger::INFO, dry_run: true)
      log.level = log_level
      log.debug("Initializing, dry_run: #{dry_run.inspect}")

      begin
        @dynamo = Aws::DynamoDB::Client.new
      rescue StandardError
        log.error('Failed to create DynamoDB client. Do you have AWS creds?')
        raise
      end
    end

    # @return [String]
    def main(_args)
      log.error('TODO: Figure out what this should do at the CLI. Read stdin?')
    end

    # @lambda_event and @lambda_context are instance variables we inherit from the parent
    def process_event
      records = @lambda_event["Records"]
      process_records(records)

    def process_records(records)
      records.each do |record|
        # puts record
        process_record(record)
      end
    end

    def process_record(record)
      body = JSON.parse(record["body"])

      ctevent = Event.new
      timestamp = DateTime.parse(body["detail"]["eventTime"])
      ctevent.timestamp = timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
      ctevent.uuid = body["detail"]["requestParameters"]["encryptionContext"]["user_uuid"]
      ctevent.context = body["detail"]["requestParameters"]["encryptionContext"]["context"]

      # get matching record
      apprecord = get_app_record(ctevent.get_key, ctevent.timestamp)
      puts apprecord.to_h
      insert_into_db(ctevent.get_key, ctevent.timestamp, body, apprecord["CWData"])
    end

    def get_app_record(uuid, timestamp)
      begin
        result = DYNAMODB_CLIENT.get_item({
          table_name: ENV["DDB_TABLE"],
          key: { "UUID" => uuid, 
                 "Timestamp" => timestamp
               },
        consistent_read: false
        })
      rescue Aws::DynamoDB::Errors::ServiceError => error
        puts "Failure adding event: "
        puts "#{error.message}"
      end
      record = result.item
    end

    def insert_into_db (uuid, timestamp, ctdata, cwdata)
      table_name = ENV["DDB_TABLE"]
      ttl = DateTime.now + 365
      ttlstring = ttl.strftime('%Y-%m-%dT%H:%M:%SZ')
      item = {
	UUID: uuid,
	Timestamp: timestamp,
	Correlated: "1",
	CTData: ctdata,
	CWData: cwdata,
	TimeToExist: ttlstring
      }
      
      params = {
	table_name: table_name,
	item: item
      }
      
      begin
	result = DYNAMODB_CLIENT.put_item(params)
	puts "Added event for user_uuid: #{uuid}"
	  
      rescue Aws::DynamoDB::Errors::ServiceError => error
	puts "Failure adding event: "
	puts "#{error.message}"
       end
    end

    def log
      return @log if @log
      @log = Logger.new(STDERR)
      @log.progname = self.class.name
      @log
    end

  end

  class Event
    def uuid=(uuid)
      @uuid = uuid
    end
    def timestamp=(timestamp)
      @timestamp = timestamp
    end
    def context=(context)
      @context = context
    end
    def uuid
      @uuid
    end
    
    def timestamp
      @timestamp
    end
    
    def context
      @context
    end
    
    def get_key()
      @uuid + '-' + @context
    end
    
    def as_json(options={})
      {
        action: @action,
        uuid: @uuid,
        timestamp: @timestamp,
        context: @context
      }
    end

    def to_json(*options)
      as_json(*options).to_json(*options)
    end
  end

end
