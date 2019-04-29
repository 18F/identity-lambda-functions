def test_event
  file = File.open File.expand_path(
                   '../../../support/test_cloudtrail_records.json', __FILE__)
  JSON.load(file)
end

ENV['AWS_REGION'] = 'castletown'
ENV['DDB_TABLE'] = 'fake_table'
ENV['RETENTION_DAYS'] = '365'
ENV['SNS_EVENT_TOPIC_ARN'] = 'arn:aws:sns:us-south:19820810:mytopic'
ENV['CT_QUEUE_URL'] = 'https://us-north.queue.amazonaws.com/19410519/login-kms-ct-events'

RSpec.describe IdentityKMSMonitor::CloudTrailToDynamoHandler do
  describe 'the process method' do
    it 'writes a match to an existing DB entry' do
      fake_sns = Aws::SNS::Client.new(stub_responses: true)
      fake_sns.stub_responses(:publish, nil)
      fake_dynamo = FakeDynamoClient.new
      fake_dynamo.put_item(
        {:table_name=>"fake_table",
         :item=>{"UUID"=>"ad891a65-4560-4669-b422-b61cd5f9c861-password-digest",
                 "Timestamp"=>"2019-03-08T13:32:07Z",
                 "CWData"=>"some cloudwatch data"}})
      instance = IdentityKMSMonitor::CloudTrailToDynamoHandler.new(dynamo: fake_dynamo, sns: fake_sns)
      instance.process_event(test_event)

      # verify the database got updated with the correlation
      final_entry = fake_dynamo.get_item(
        {:table_name=>"fake_table",
         :key=>{"UUID"=>"ad891a65-4560-4669-b422-b61cd5f9c861-password-digest",
                "Timestamp"=>"2019-03-08T13:32:07Z"}})
      expect(final_entry.item['Correlated']).to eq '1'

      # verify we published the correlation message to SNS
      sns_message = JSON.parse(
        fake_sns.api_requests[0][:params][:message])
      expect(sns_message['correlated']).to be true
    end
    it 'requeues an entry when no matching database entry exists' do
      fake_sqs = Aws::SQS::Client.new(stub_responses: true)
      fake_sqs.stub_responses(:send_message, nil)
      fake_dynamo = FakeDynamoClient.new
      instance = IdentityKMSMonitor::CloudTrailToDynamoHandler.new(dynamo: fake_dynamo, sqs: fake_sqs)
      instance.process_event(test_event)

      # verify that it requeued the event with a higher RetryCount
      requeued_event = fake_sqs.api_requests[0]
      retrycount = requeued_event[:params][:message_attributes]["RetryCount"][
        :string_value]
      expect(retrycount).to eq '3'
    end
    it 'alerts SNS when retries are all used up' do
      retried_event = test_event
      retried_event["Records"][0]["messageAttributes"]["RetryCount"][
        "stringValue"] = '5'
      fake_sns = Aws::SNS::Client.new(stub_responses: true)
      fake_sns.stub_responses(:publish, nil)
      fake_dynamo = FakeDynamoClient.new
      instance = IdentityKMSMonitor::CloudTrailToDynamoHandler.new(dynamo: fake_dynamo, sns: fake_sns)
      instance.process_event(retried_event)

      # verify we published the correlation message to SNS
      sns_message = JSON.parse(
        fake_sns.api_requests[0][:params][:message])
      expect(sns_message['correlated']).to be false
    end
  end
end
