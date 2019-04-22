# frozen_string_literal: true
require 'aws-sdk-waf'
require 'aws-sdk-wafregional'
require 'logger'

module IdentityReputationLists

  # Class for updating AWS WAF IPSets
  class AwsIPSetUpdater < Functions::AbstractLambdaHandler

    # Make this accessible via CLI
    Functions.register_handler(self, 'update-reputation-list-ipset')

    attr_reader :waf

    def initialize(log_level: Logger::INFO, dry_run: true)
      super

      begin
        @waf = Aws::WAFRegional::Client.new
      rescue StandardError
        log.error('Failed to create WAF client. Do you have AWS creds?')
        raise
      end
    end

    def cli_main
      update_ipset
    end

    def change_token
      @waf.get_change_token.change_token
    end

    def update_ip_set
      ip_set_id = IdentityReputationLists::Config.new.data.
        fetch('identity-reputation-lists').
        fetch('ip_set_id')

      # batch process 1000 at a time otherwise it will throw the following error:
      # Aws::WAFRegional::Errors::WAFLimitsExceededException (Operation would result in exceeding resource limits.)
      # https://docs.aws.amazon.com/waf/latest/developerguide/limits.html
      if dry_run?
        log.info('[DRY RUN] Would have updated the ipset')
        log.info("\n[DRY RUN]:\n" +)
        return { ip_set_id: ip_set_id }
      else
        log.debug("About to update IP Set ID: #{ip_set_id}")
      end
      reputation_list_updates.each_slice(1000) do |ip_set_update_batch|
        @waf.update_ip_set({
          change_token: change_token,
          ip_set_id: ip_set_id,
          updates: ip_set_update_batch,
        })
      end
    end

    def reputation_list_updates
      ipset_updates = []

      ips = ReputationListParser.new.parse_lists

      ips.each do |ip|
        update = {
          action: "INSERT",
          ip_set_descriptor: {
            type: "IPV4",
            value: ip
          }
        }

        ipset_updates << update
      end

      ipset_updates
    end
  end
end
