# frozen_string_literal: true

require 'fileutils'
require 'logger'
require 'tempfile'
require 'tmpdir'

require 'octokit'
require 'subprocess'

require 'aws-sdk-secretsmanager'

module IdentityAudit

  # Wrapper class to handle cloning git repos using an SSH key pulled from AWS
  # Secrets Manager.
  class RepoCloner
    attr_reader :ssh_key_secret_id
    attr_reader :aws_sm

    # Convenience wrapper to fetch SSH key, clone a repo, and read the
    # specified file path.
    def self.read_team_yml(team_yml_repo:, team_yml_path:,
                           secret_id_for_ssh_key:)
      rc = RepoCloner.new(secret_id_for_ssh_key: secret_id_for_ssh_key)
      rc.with_clone_to_tmp(team_yml_repo) do |checkout|
        rc.log.info('Reading team.yml from checkout')
        return File.read(File.join(checkout, team_yml_path))
      end
    end

    # Same as .read_team_yml but configure arguments using the JSON config.
    # Override using config.json.
    def self.read_team_yml_using_config
      config = IdentityAudit::Config.new.data.fetch('identity-audit')
      team_yml_repo = config.fetch('team_yml_git_url')
      team_yml_path = config.fetch('team_yml_relative_path')
      secret_id_for_ssh_key = config.fetch('secret_id_for_ssh_key')
      read_team_yml(team_yml_repo: team_yml_repo, team_yml_path: team_yml_path,
                    secret_id_for_ssh_key: secret_id_for_ssh_key)
    end

    def initialize(secret_id_for_ssh_key:)
      @ssh_key_secret_id = secret_id_for_ssh_key
      @aws_sm = Aws::SecretsManager::Client.new
    end

    def log
      return @log if @log
      @log = Logger.new(STDERR)
      @log.progname = self.class.name
      @log
    end

    def with_clone_to_tmp(clone_url)
      unless block_given?
        raise ArgumentError.new('Must pass block to execute before rm')
      end
      tmpdir = Dir.mktmpdir('repo-cloner.')
      with_ssh_key do |tmpf|
        clone(clone_url: clone_url, target_dir: tmpdir, ssh_key_path: tmpf)
      end
      yield tmpdir
    ensure
      FileUtils.remove_entry_secure(tmpdir, true) if tmpdir
    end

    # @param [String] clone_url The SSH URL to clone
    # @param [String] target_dir The target directory to clone into
    # @param [String] ssh_key_path Path to the SSH key to use to connect
    def clone(clone_url:, target_dir:, ssh_key_path: nil)
      env = {}
      env['GIT_SSH_COMMAND'] = "ssh -i #{ssh_key_path}" if ssh_key_path
      log.info { 'env: ' + env.inspect }

      cmd = %W[git clone #{clone_url} #{target_dir}]
      log.info { '+ ' + cmd.join(' ') }

      Subprocess.check_call(cmd, env: env)
      log.info('Clone complete')
    end

    private

    # @return [String] SSH private key string
    def retrieve_ssh_key
      log.info('Retrieving SSH key from secrets manager at ' +
               ssh_key_secret_id.inspect)
      aws_sm.get_secret_value(secret_id: ssh_key_secret_id).secret_string
    end

    # Retrieve SSH key from AWS secrets manager and yield the path to the
    # temporary file containing the SSH key.
    #
    # @yieldparam [String]
    #
    def with_ssh_key
      unless block_given?
        raise ArgumentError.new('Must pass block to execute with SSH key')
      end

      key = retrieve_ssh_key

      tmpf = Tempfile.create('repo-cloner.ssh-key.')
      tmpf.write(key)
      tmpf.close
      log.info('Saved SSH key to ' + tmpf.path)

      yield tmpf.path
    ensure
      File.unlink(tmpf.path)
    end
  end
end
