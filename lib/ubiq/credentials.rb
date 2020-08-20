# Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
#
# NOTICE:  All information contained herein is, and remains the property
# of Ubiq Security, Inc. The intellectual and technical concepts contained
# herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
# covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law. Dissemination of this
# information or reproduction of this material is strictly forbidden
# unless prior written permission is obtained from Ubiq Security, Inc.
#
# Your use of the software is expressly conditioned upon the terms
# and conditions available at:
#
#     https://ubiqsecurity.com/legal
#

# frozen_string_literal: true

require 'configparser'
require 'rb-readline'
require 'byebug'

module Ubiq
  # Access Credentials used by the library to validate service calls
  class CredentialsInfo
    def initialize(access_key_id, secret_signing_key, secret_crypto_access_key, host)
      @access_key_id = access_key_id
      @secret_signing_key = secret_signing_key
      @secret_crypto_access_key = secret_crypto_access_key
      @host = host
    end

    def set_attributes
      return OpenStruct.new(
        access_key_id: @access_key_id,
        secret_signing_key: @secret_signing_key,
        secret_crypto_access_key: @secret_crypto_access_key,
        host: @host
        )
    end
  end

  # Class to load a credentials file or the default
  # and read the credentials from either a supplied
  # profile or use the default
  class ConfigCredentials < CredentialsInfo
    def initialize(config_file, profile)
      # If config file is not found
      if !config_file.nil? && !File.exist?(config_file)
        raise RuntimeError, "Unable to open config file #{config_file} or contains missing values"
      end

      if config_file.nil?
        config_file = '~/.ubiq/credentials'
      end

      # If config file is found
      if File.exist?(File.expand_path(config_file))
        @creds = load_config_file(config_file, profile)
      end
    end

    def get_attributes
      return @creds
    end

    def load_config_file(file, profile)
      config = ConfigParser.new(File.expand_path(file))

      # Create empty dictionaries for the default and supplied profile
      p = {}
      d = {}

      # get the default profile if there is one
      if config['default'].present?
        d = config['default']
      end

      # get the supplied profile if there is one
      if config[profile].present?
        p = config[profile]
      end

      # Use given profile if it is available, otherwise use default.
      access_key_id = p.key?('ACCESS_KEY_ID') ? p['ACCESS_KEY_ID'] : d['ACCESS_KEY_ID']
      secret_signing_key = p.key?('SECRET_SIGNING_KEY') ? p['SECRET_SIGNING_KEY'] : d['SECRET_SIGNING_KEY']
      secret_crypto_access_key = p.key?('SECRET_CRYPTO_ACCESS_KEY') ? p['SECRET_CRYPTO_ACCESS_KEY'] : d['SECRET_CRYPTO_ACCESS_KEY']
      host = p.key?('SERVER') ? p['SERVER'] : d['SERVER']

      # If the provided host does not contain http protocol then add to it
      if !host.include?('http://') && !host.include?('https://')
        host = 'https://' + host
      end

      return CredentialsInfo.new(access_key_id, secret_signing_key, secret_crypto_access_key, host).set_attributes
    end
  end

  # Class where the credentials can be explicitly set or
  # will use the Environment variables instead
  class Credentials < CredentialsInfo
    def initialize(papi, sapi, srsa, host)
      @access_key_id = papi.present? ? papi : ENV['UBIQ_ACCESS_KEY_ID']
      @secret_signing_key = sapi.present? ? sapi : ENV['UBIQ_SECRET_SIGNING_KEY']
      @secret_crypto_access_key = srsa.present? ? srsa : ENV['UBIQ_SECRET_CRYPTO_ACCESS_KEY']
      @host = host.present? ? host : ENV['UBIQ_SERVER']
    end

    @creds = CredentialsInfo.new(@access_key_id, @secret_signing_key, @secret_crypto_access_key, @host).set_attributes

    def get_attributes
      return @creds
    end
  end
end
