# frozen_string_literal: true

require 'active_model'
require 'active_support'
require 'active_support/core_ext'
require 'zeitwerk'

loader = Zeitwerk::Loader.for_gem
loader.setup

module Sisjwt
  KEY_ID_ENV_NAME = 'SISJWT_KEY_ID'
  TOKEN_TYPE_DEV = 'SISKMSd'
  TOKEN_TYPE_V1 = 'SISKMS1.0'

  Error = Class.new(StandardError)
  FileNotFoundError = Class.new(Error)
  KeyNotFoundError = Class.new(Error)
  InventoryFileError = Class.new(Error)
end
