# frozen_string_literal: true

require 'faraday'
require 'ipaddress'
require 'logger'

module IdentityReputationLists
  # Parses reputation lists for IPs
  class ReputationListParser
    IP_OR_CIDR = /([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\/?([0-9]{1,2})/

    # parse each line of the response from the urls in the config and capture
    # ip addresses or address blocks into an array.
    def parse_lists
      ip_addresses = []
      config = Config.new.data.fetch('identity-reputation-lists')

      config.fetch("urls").each do |url|
        response = Faraday.get(url)
        response.body.each_line do |line|
          if line.match(IP_OR_CIDR)
            ip = IPAddress::IPv4.new(line.match(IP_OR_CIDR)[0])
            ip_addresses << ip.to_string unless ip.to_string.end_with?('/12') || ip.to_string.end_with?('/14') || ip.to_string.end_with?('/15')
          end
        end
      end

      ip_addresses.uniq
    end
  end
end
