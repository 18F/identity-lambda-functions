file = File.open "spec/unit/kms_monitor/test_cloudtrail_records.json"
test_records = JSON.load(file)

class FakeDynamoClient
  def inner_client
    @inner_client ||= Aws::DynamoDB::Client.new(stub_responses: true)
  end

  # We'll keep a hash of [table, uuid, timestamp] to records
  def objects
    @objects ||= {}
  end

  def get_item(params)
    puts "get_item",params
    table_name = params[:table_name]
    key = params[:key]
    uuid = key['UUID']
    timestamp = key['timestamp']
    object_key = [table_name, uuid, timestamp]
    inner_client.stub_responses(:get_item, {item: objects[object_key]})
    inner_client.get_item(nil)
  end

  def put_item(params)
    puts "put_item",params
    table_name = params[:table_name]
    item = params[:item]
    uuid = item['UUID']
    timestamp = item['timestamp']
    object_key = [table_name, uuid, timestamp]
    objects[object_key] = item
  end
end

RSpec.describe IdentityKMSMonitor::CloudTrailToDynamoHandler do
  describe 'something in the cloudtrail class' do
    it 'passes the happy case' do
      ENV['DDB_TABLE'] = 'fake_table'
      fake_dynamo = FakeDynamoClient.new
      fake_dynamo.put_item({:table_name=>"fake_table", :item=>{"UUID"=>"ad891a65-4560-4669-b422-b61cd5f9c861-password-digest", "Timestamp"=>"2019-03-08T13:32:07Z", "CWData"=>"some cloudwatch data"}})
      allow(Aws::DynamoDB::Client).to receive(:new).with(hash_including(:stub_responses => false))) and_return(fake_dynamo)

      instance = IdentityKMSMonitor::CloudTrailToDynamoHandler.new
      instance.inner_process(test_records)
      expect(instance.dynamo).to be
    end
  end
end
