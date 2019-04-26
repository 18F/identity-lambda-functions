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
    object_key = object_key(params[:table_name], params[:key])
    inner_client.stub_responses(:get_item, {item: objects[object_key]})
    inner_client.get_item(params)
  end

  def put_item(params)
    item = params[:item]
    object_key = object_key(params[:table_name], item)
    objects[object_key] = item
  end
end
