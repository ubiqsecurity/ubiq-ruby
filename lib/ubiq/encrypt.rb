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

require 'rb-readline'
require 'byebug'
require 'httparty'
require 'active_support/all'
require_relative './auth.rb'
require_relative './algo.rb'
require 'webrick'

# Ubiq Security Modules for encrypting / decrypting data
module Ubiq
  # Ubiq Encryption object
  # This object represents a single data encryption key and can be used to
  # encrypt several  separate plain texts using the same key
  class Encryption
    def initialize(creds, uses)
      raise 'Some of your credentials are missing, please check!' unless validate_creds(creds)

      # Set host, either the default or the one given by caller
      @host = creds.host.blank? ? UBIQ_HOST : creds.host

      # Set the credentials in instance varibales to be used among methods
      # The client's public API key (used to identify the client to the server
      @papi = creds.access_key_id

      # The client's secret API key (used to authenticate HTTP requests)
      @sapi = creds.secret_signing_key

      # The client's secret RSA encryption key/password (used to decrypt the
      # client's RSA key from the server). This key is not retained by this object.
      @srsa = creds.secret_crypto_access_key

      # Build the endpoint URL
      url = endpoint_base + '/encryption/key'

      # Build the Request Body with the number of uses of key
      query = { uses: uses }

      # Retrieve the necessary headers to make the request using Auth Object
      headers = Auth.build_headers(@papi, @sapi, endpoint, query, @host, 'post')

      @encryption_started = false
      @encryption_ready = true

      # Request a new encryption key from the server. if the request
      # fails, the function raises a HTTPError indicating
      # the status code returned by the server. this exception is
      # propagated back to the caller

      begin
        response = HTTParty.post(
          url,
          body: query.to_json,
          headers: headers
        )
      rescue HTTParty::Error
        raise 'Cant reach server'
      end

      # Response status is 201 Created
      if response.code == WEBrick::HTTPStatus::RC_CREATED
        # The code below largely assumes that the server returns
        # a json object that contains the members and is formatted
        # according to the Ubiq REST specification.

        # Build the key object
        @key = {}
        @key['id'] = response['key_fingerprint']
        @key['session'] = response['encryption_session']
        @key['security_model'] = response['security_model']
        @key['algorithm'] = response['security_model']['algorithm'].downcase
        @key['max_uses'] = response['max_uses']
        @key['uses'] = 0
        @key['encrypted'] = Base64.strict_decode64(response['encrypted_data_key'])

        # Get encrypted private key from response body
        encrypted_private_key = response['encrypted_private_key']
        # Get wrapped data key from response body
        wrapped_data_key = response['wrapped_data_key']
        # Decrypt the encryped private key using @srsa supplied
        private_key = OpenSSL::PKey::RSA.new(encrypted_private_key, @srsa)
        # Decode WDK from base64 format
        wdk = Base64.strict_decode64(wrapped_data_key)
        # Use private key to decrypt the wrapped data key
        dk = private_key.private_decrypt(wdk, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        @key['raw'] = dk
        # Build the algorithm object
        @algo = Algo.new.get_algo(@key['algorithm'])
      else
        # Raise the error if response is not 201
        raise "HTTPError Response: Expected 201, got #{response.code}"
      end
    end

    def begin
      # Begin the encryption process

      # When this function is called, the encryption object increments
      # the number of uses of the key and creates a new internal context
      # to be used to encrypt the data.
      # If the encryption object is not yet ready to be used, throw an error
      raise 'Encryption not ready' unless @encryption_ready

      # if Encryption cipher context already exists
      raise 'Encryption already in progress' if @encryption_started
      # If max uses > uses
      raise 'Maximum key uses exceeded' if @key['uses'] >= @key['max_uses']

      @key['uses'] += 1
      # create a new Encryption context and initialization vector
      @enc, @iv = Algo.new.encryptor(@algo, @key['raw'])

      # Pack the result into bytes to get a byte string
      struct = [0, 0, @algo[:id], @iv.length, @key['encrypted'].length].pack('CCCCn')
      @encryption_started = true
      return struct + @iv + @key['encrypted']
    end

    def update(data)
      raise 'Encryption is not Started' unless @encryption_started

      # Encryption of some plain text is perfomed here
      # Any cipher text produced by the operation is returned
      @enc.update(data)
    end

    def end
      raise 'Encryption is not Started' unless @encryption_started

      # This function finalizes the encryption (producing the final
      # cipher text for the encryption, if necessary) and adds any
      # authentication information (if required by the algorithm).
      # Any data produced is returned by the function.

      # Finalize an encryption
      res = @enc.final
      if @algo[:tag_length] != 0
        # Add the tag to the cipher text
        res += @enc.auth_tag
      end
      @encryption_started = false
      # Return the encrypted result
      return res
    end

    def close
      raise 'Encryption currently running' if @encryption_started

      # If the key was used less times than was requested, send an update to the server
      if @key['uses'] < @key['max_uses']
        query_url = "#{endpoint}/#{@key['id']}/#{@key['session']}"
        url = "#{endpoint_base}/encryption/key/#{@key['id']}/#{@key['session']}"
        query = { actual: @key['uses'], requested: @key['max_uses'] }
        headers = Auth.build_headers(@papi, @sapi, query_url, query, @host, 'patch')
        response = HTTParty.patch(
          url,
          body: query.to_json,
          headers: headers
        )
        remove_instance_variable(:@key)
        @encryption_ready = false
      end
    end

    def endpoint_base
      @host + '/api/v0'
    end

    def endpoint
      '/api/v0/encryption/key'
    end

    def validate_creds(credentials)
      # This method checks for the presence of the credentials
      !credentials.access_key_id.blank? &&
        !credentials.secret_signing_key.blank? &&
        !credentials.secret_crypto_access_key.blank?
    end
  end

  def validate_creds(credentials)
    # This method checks for the presence of the credentials
    !credentials.access_key_id.blank? &&
      !credentials.secret_signing_key.blank? &&
      !credentials.secret_crypto_access_key.blank?
  end

  def encrypt(creds, data)
    begin
      enc = Encryption.new(creds, 1)
      res = enc.begin + enc.update(data) + enc.end
      enc.close
    rescue StandardError
      enc&.close
      raise
    end
    return res
  end
end

