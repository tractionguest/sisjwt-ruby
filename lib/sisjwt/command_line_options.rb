# frozen_string_literal: true

require 'optparse'

module Sisjwt
  # Processes command-line arguments for +./bin/sisjwt+.
  # @see CommandLine
  class CommandLineOptions < OptionParser
    VERBOSITY_LEVELS = {
      0 => Logger::UNKNOWN,
      1 => Logger::FATAL,
      2 => Logger::ERROR,
      3 => Logger::WARN,
      4 => Logger::INFO,
      5 => Logger::DEBUG
    }.freeze

    attr_reader :app

    def initialize(app)
      @app = app

      super do |opts|
        create_options(opts)
        yield opts if block_given?
      end
    end

    private

    def create_options(opts) # rubocop:disable Metrics/AbcSize,Metrics/MethodLength
      opts.banner = 'sisjwt - Sign in Solutions JWT Generator'

      opts.on('--[no-]strict-mode',
              "Turn off strict mode to allow specifying invalid values, default strict: #{app.strict_mode}") do |v|
        app.strict_mode = v
      end

      opts.on('--verbose=LEVEL', 'Set the verbosity level, 1-5. The higher the number the more verbose') do |v|
        app.logger.level = convert_verbosity_level_to_log_level(v)
        app.logger.warn "Verbosity FLAG; level=#{app.logger.level}"
      end

      opts.on('-v',
              "Increase the verbosity. Can specify more than once. Default is -#{'v' * default_verbosity_level}; " \
              'use --verbose if you wish to set a lower value.') do |_v|
        current_vebosity_level = convert_log_level_to_verbosity_level(app.logger.level)
        if current_vebosity_level < VERBOSITY_LEVELS.size - 1
          new_verbosity_level = current_vebosity_level + 1
          app.logger.level = convert_verbosity_level_to_log_level(new_verbosity_level)
          app.logger.debug "Verbosity FLAG; level=#{current_vebosity_level} logl=#{app.logger.level}"
        else
          app.logger.warn "NOT increasing verbosity; already at higest level=#{current_vebosity_level}"
        end
      end

      opts.on('-s', '--silent', 'Do not output any logs or anything that is not data.  Same as --verbose=0') do |_v|
        app.logger.level = Logger::UNKNOWN
      end

      opts.on('-t', '--type=val', "Type of Token to Generate, default #{app.token_type}") do |v|
        app.token_type = v
      end

      opts.on('-a', '--alg=val', "KMS Algorithm to use to sign the token, default #{app.key_alg}") do |v|
        app.key_alg = v
      end

      opts.on('-r', '--region=val', "KMS Region to use to sign the token, default #{app.aws_region}") do |v|
        app.aws_region = v
      end

      opts.on('-e', '--expires=secs', OptionParser::DecimalInteger,
              'Number of seconds that the key should be valid for (used to calculate `exp` value), ' \
              "default #{app.token_lifetime}s") do |v|
        app.aws_region = v.to_i
      end

      opts.on '--aud=VAL', "Token AUDience (Should be SIS company acronym: SIE, SIC, etc), default #{app.aud}" do |v|
        app.aud = v
      end

      opts.on('--iss=VAL', "Token ISSuer (Should be SIS company acronym: SIE, SIC, etc), default #{app.iss}") do |v|
        app.iss = v
      end

      opts.on('--exp=VAL', OptionParser::DecimalInteger, "Token EXPiration, unix time, default #{app.exp}") do |v|
        app.exp = v
      end

      opts.on('--ttl=VAL', OptionParser::DecimalInteger,
              "Token Time To Live, seconds, default #{app.token_lifetime}s") do |v|
        app.exp = v
      end
    end

    def default_verbosity_level
      ENV.fetch('SISJWT_VERBOSE', convert_log_level_to_verbosity_level(Logger::WARN))
    end

    def convert_verbosity_level_to_log_level(verb_level)
      VERBOSITY_LEVELS[verb_level.to_i].to_i
    end

    def convert_log_level_to_verbosity_level(log_level)
      verb_level, = VERBOSITY_LEVELS.detect { |_, v| v == log_level }
      verb_level.to_i
    end
  end
end
