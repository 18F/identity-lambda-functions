file = File.open File.expand_path(
                   '../../../support/test_cloudtrail_records.json', __FILE__)

test_event = JSON.load(file)

RSpec.describe IdentityKMSMonitor::CloudTrailToDynamoHandler do
  describe 'the process method' do
    it 'writes a match to an existing DB entry' do
      ENV['DDB_TABLE'] = 'fake_table'
      fake_dynamo = FakeDynamoClient.new
      fake_dynamo.put_item(
        {:table_name=>"fake_table",
         :item=>{"UUID"=>"ad891a65-4560-4669-b422-b61cd5f9c861-password-digest",
                 "Timestamp"=>"2019-03-08T13:32:07Z",
                 "CWData"=>"some cloudwatch data"}})
      instance = IdentityKMSMonitor::CloudTrailToDynamoHandler.new(dynamo: fake_dynamo)
      instance.process_event(test_event)
      final_entry = fake_dynamo.get_item(
        {:table_name=>"fake_table",
         :key=>{"UUID"=>"ad891a65-4560-4669-b422-b61cd5f9c861-password-digest",
                "Timestamp"=>"2019-03-08T13:32:07Z"}})
      expect(final_entry.item['Correlated']).to eq '1'
    end
  end
end
