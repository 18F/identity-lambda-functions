# frozen_string_literal: true

require 'logger'
require 'base64'

require 'aws-sdk-secretsmanager'

module IdentityAudit

  # Wrapper class to handle fetching content from a Github repo.
  class RepoContent
    # Octokit client
    attr_reader :octokit

    # Retrieve Team.yml from the specified Github repo
    #
    # @param [String] team_yml_repo The repo where team.yml can be found, e.g.
    #   "myorg/myrepo"
    # @param [String] team_yml_path Path within the repo to team.yml, e.g.
    #   "team/team.yml"
    # @param [Octokit::Client] octokit_client
    #
    def self.read_team_yml(team_yml_repo:, team_yml_path:, octokit_client: nil)
      rc = RepoContent.new(octokit_client: octokit_client)
      rc.read_team_yml_via_github_api(repo: team_yml_repo, path: team_yml_path)
    end

    # Same as .read_team_yml but configure arguments using the JSON config.
    # Override using config.json.
    def self.read_team_yml_using_config(octokit_client: nil)
      config = IdentityAudit::Config.new.data.fetch('identity-audit')
      team_yml_repo = config.fetch('team_yml_github_repo')
      team_yml_path = config.fetch('team_yml_relative_path')
      read_team_yml(team_yml_repo: team_yml_repo, team_yml_path: team_yml_path,
                    octokit_client: octokit_client)
    end

    def initialize(octokit_client: nil)
      @octokit = octokit_client || octokit_client_from_github_auditor
    end

    def read_team_yml_via_github_api(repo:, path:)
      repo_url = 'https://github.com/' + repo
      log.info("Fetching team.yml from #{repo_url} at #{path.inspect}")
      resp = octokit.contents(repo, path: path)
      log.info("Received git object #{resp.sha.inspect}, #{resp.size} bytes")
      case resp.encoding
      when 'base64'
        Base64.decode64(resp.content)
      else
        raise "Unexpected response content encoding: #{resp.encoding.inspect}"
      end
    end

    def log
      return @log if @log
      @log = Logger.new(STDERR)
      @log.progname = self.class.name
      @log
    end

    private

    def octokit_client_from_github_auditor
      log.info('Getting Octokit client from GithubAuditor')
      ga = IdentityAudit::GithubAuditor.new(dry_run: true)
      ga.ok
    end
  end
end