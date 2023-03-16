# frozen_string_literal: true

module Sisjwt
  # An interface for reading / interacting with an ARN inventory file that can be
  # provided by DevOps team to validate which ARNs are assigned to which issuers
  class ArnInventory
    def initialize
      @inventory = {}
    end

    # @param path [string]
    # @param env [string]
    def add_from_config(path, env: nil)
      expanded_file_contents = read_expand_erb_file(path)
      config_file = YAML.safe_load(expanded_file_contents).with_indifferent_access

      env ||= ENV.fetch('RAILS_ENV', 'development')
      unless config_file.key?(env)
        raise InventoryFileError, "Could not find requested environment (#{env}) in inventory file #{path}"
      end
      raise InventoryFileError, 'Inventory file is malformed!' unless config_file[env].is_a?(Hash)

      @inventory = config_file[env]
    end

    # @return [boolean]
    def empty?
      @inventory.empty?
    end

    # @param issuer [string,symbol]
    # @param arn [string]
    # @return [boolean]
    def valid_arn?(issuer, arn)
      @inventory.key?(issuer) && @inventory[issuer].include?(arn)
    end

    # @param arn [string]
    # @return [boolean]
    def find_issuer(arn)
      @inventory.each do |iss, arns|
        return iss if arns.include?(arn)
      end

      nil
    end

    private

    # Reads file given by path and treats it as an ERB template
    # rending it and returning the contents that can then be
    # parsed further (i.e. by YAML.safe_load)
    def read_expand_erb_file(path)
      path = Pathname(path)
      raise FileNotFoundError, path unless path.file?

      erb = ERB.new(path.read)
      erb.filename = path.to_s
      erb.result binding
    end
  end
end
