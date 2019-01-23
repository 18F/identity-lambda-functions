#!/usr/bin/env ruby
# frozen_string_literal: true

require 'bundler/setup'
require_relative './lib/audit'

# Parent class for lambda handlers
class AbstractLambdaHandler
  def self.klass
    raise NotImplementedError.new('Must override klass to point to runner')
  end

  def self.process(event:, context:)
    cli_run
    _ = [event, context]
  end

  def self.cli_run(args)
    if ENV['DEBUG'] && !ENV['DEBUG'].empty?
      dry_run = true
      log_level = Logger::DEBUG
    else
      dry_run = false
      log_level = Logger::INFO
    end
    ga = klass.new(log_level: log_level, dry_run: dry_run)
    ga.main(args)
  end
end

# Top level lambda function wrapper module
module Functions

  # Add lamba function classes in here. They should respond to the class
  # methods (not instance methods):
  # - .process()
  # - .cli_run()
  # - .cli_name()

  def self.known_classes
    Functions.constants.map { |c| Functions.const_get(c) }
             .select { |c| c.is_a?(Class) }
  end

  def self.get_class(cli_name)
    klass = known_classes.find { |c| c.cli_name == cli_name }
    unless klass
      raise KeyError.new('Could not find class named ' + cli_name.inspect)
    end
    klass
  end

  # Lambda handler for audit-github
  class GithubAuditHandler < AbstractLambdaHandler
    def self.klass
      IdentityAudit::GithubAuditor
    end

    def self.cli_name
      'audit-github'
    end
  end

  # Lambda handler for audit-aws
  class AWSAuditHandler < AbstractLambdaHandler
    def self.klass
      IdentityAudit::AwsIamAuditor
    end

    def self.cli_name
      'audit-aws'
    end
  end
end

def cli_main
  if ARGV.empty?
    STDERR.puts "usage: #{$0} LAMBDA [ARGS...]\n\n"
    STDERR.puts 'known lambdas:'
    Functions.known_classes.each do |c|
      puts '  - ' + c.cli_name
    end
    STDERR.puts
    STDERR.puts('Set DEBUG=1 to enable dry run and debug output')

    exit 1
  end

  command_name = ARGV.shift

  klass = Functions.get_class(command_name)
  klass.cli_run(ARGV)
end

if $0 == __FILE__
  cli_main
end
