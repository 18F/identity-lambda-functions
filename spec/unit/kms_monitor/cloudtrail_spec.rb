RSpec.describe IdentityKMSMonitor::CloudTrailToDynamoHandler do
  describe 'something in the cloudtrail class' do
    it 'does anything at all' do
      instance = IdentityKMSMonitor::CloudTrailToDynamoHandler.new
      expect(instance.dynamo).to be
    end
  end
end
