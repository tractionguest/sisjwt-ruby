# frozen_string_literal: true

module Sisjwt
  # Provides a command-line interface to {SisJwt}, allowing users to sign or
  # verify tokens.
  #
  # @see {#call}
  class CommandLine
    attr_accessor :jwt_opts, :logger, :strict_mode

    (
      %i[token_type key_alg key_id aws_region token_lifetime iss aud iat exp] +
      %i[token_type= key_alg= key_id= aws_region= token_lifetime= iss= aud= iat= exp=] +
      %i[validate valid? errors error_messages]
    ).each do |m|
      delegate m, to: :jwt_opts
    end

    # Creates a new App instance from given options
    def self.from_options!(options = ARGV, logger: nil)
      new(logger: logger).tap do |app|
        opt_parser = CommandLineOptions.new(app)
        opt_parser.parse!(options)
        app.validate
        app.logger.debug("Strict Mode: #{app.strict_mode}")
        app.logger.debug(" Opts Valid: #{app.valid?}")

        abort opt_parser.help if options.empty?
      end
    end

    def initialize(logger: nil)
      @jwt_opts = SisJwtOptions.defaults(mode: :verify)
      @strict_mode = true
      @logger = logger || Logger.new($stderr, level: :warn)
      @logger.debug("Is Prod: #{production?}")
    end

    def call(cmd)
      logger.progname = "#{logger.progname}-#{cmd}"
      case cmd
      when 'sign' then sign_token
      when 'verify' then verify_token
      else
        logger.fatal("Unknown command: #{cmd}")
        exit 1
      end
    end

    def to_h
      {
        production: production?, token_type: token_type,
        key_alg: key_alg, key_id: key_id,
        aws_region: aws_region, token_lifetime: token_lifetime,
        iss: iss, aud: aud, iat: iat, exp: exp
      }
    end

    def production?
      Runtime.production_env?
    end

    # Transforms array like:
    #    [ "k=v", "val", "other=opt" ]
    # into
    #    { "k" => "v", "val" => nil, "other" => "opt" }
    def array_to_hash(array)
      array.to_h do |v|
        k, v = v.split('=', 2)
        [k.strip, v&.strip]
      end.with_indifferent_access
    end

    def sign_token(args = ARGV)
      logger.info('SIGN TOKEN')
      args = array_to_hash(args) if args.is_a?(Array)

      logger.debug("config: #{to_h}")
      logger.debug("  args: #{args}")

      sisjwt = SisJwt.new(jwt_opts, logger: logger)
      token = sisjwt.encode(args)

      # We explictitly do not use logger here because we want it to goto stdout
      $stdout.puts token
    end

    def verify_token(token = ARGV[0])
      logger.info('VERIFY TOKEN')
      token = prompt_token if token == '-'
      verification = token_verification(token)

      logger.debug("config: #{to_h}")
      logger.debug(" token: #{token}")

      # We explictitly do not use logger here because we want it to goto stdout
      $stdout.puts(verification.to_json)
    end

    def prompt_token
      logger.debug('Reading token from stdin...')
      $stdin.read
    end

    def token_verification(token)
      SisJwt.new(jwt_opts, logger: logger).verify(token).tap do |verification|
        verification.add_allowed_aud(aud)
        verification.add_allowed_iss(iss)
      end
    end
  end
end
