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

  def object_key(table_name, item)
    uuid = item["UUID"]
    timestamp = item["Timestamp"]
    [table_name, uuid, timestamp]
  end

  def get_item(params)
    puts "get_item: #{params}"
    object_key = object_key(params[:table_name], params[:key])
    puts "object_key: #{object_key}"
    inner_client.stub_responses(:get_item, {item: objects[object_key]})
    inner_client.get_item(params)
  end

  def put_item(params)
    puts "put_item: #{params}"
    item = params[:item]
    object_key = object_key(params[:table_name], item)
    puts "object_key: #{object_key}"
    objects[object_key] = item
  end
end

RSpec.describe IdentityKMSMonitor::CloudTrailToDynamoHandler do
  describe 'something in the cloudtrail class' do
    it 'writes a match to an existing DB entry' do
      ENV['DDB_TABLE'] = 'fake_table'
      fake_dynamo = FakeDynamoClient.new
      fake_dynamo.put_item(
        {:table_name=>"fake_table",
         :item=>{"UUID"=>"ad891a65-4560-4669-b422-b61cd5f9c861-password-digest",
                 "Timestamp"=>"2019-03-08T13:32:07Z",
                 "CWData"=>"some cloudwatch data"}})
      instance = IdentityKMSMonitor::CloudTrailToDynamoHandler.new(dynamo: fake_dynamo)
      instance.inner_process(test_records)
      final_entry = fake_dynamo.get_item(
        {:table_name=>"fake_table",
         :key=>{"UUID"=>"ad891a65-4560-4669-b422-b61cd5f9c861-password-digest",
                "Timestamp"=>"2019-03-08T13:32:07Z"}})
      puts "final_entry: ", final_entry
      expect(final_entry.item['Correlated']).to eq '1'
    end
  end
end
