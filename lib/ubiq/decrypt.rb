# frozen_string_literal: true

require 'rb-readline'
require 'httparty'
require 'active_support/all'
require_relative './auth.rb'
require_relative './algo.rb'
require_relative './encrypt.rb'
require 'webrick'

# Ubiq Security Modules for encrypting / decrypting data
module Ubiq
  # Class to provide data decryption, either as a simple
  # single function call or as a piecewise where the
  # entire data element isn't available at once or is
  # too large to process in a single call.
  class Decryption
    def initialize(creds)
      # Initialize the decryption module object
      # Set the credentials in instance varibales to be used among methods
      # the server to which to make the request
      raise 'Some of your credentials are missing, please check!' unless validate_creds(creds)

      @host = creds.host.blank? ? UBIQ_HOST : creds.host

      # The client's public API key (used to identify the client to the server
      @papi = creds.access_key_id

      # The client's secret API key (used to authenticate HTTP requests)
      @sapi = creds.secret_signing_key

      # The client's secret RSA encryption key/password (used to decrypt the
      # client's RSA key from the server). This key is not retained by this object.
      @srsa = creds.secret_crypto_access_key

      @decryption_ready = true
      @decryption_started = false

    end

    def endpoint_base
      @host + '/api/v0'
    end

    def endpoint
      '/api/v0/decryption/key'
    end

    def begin
      # Begin the decryption process

      # This interface does not take any cipher text in its arguments
      # in an attempt to maintain an API that corresponds to the
      # encryption object. In doing so, the work that can take place
      # in this function is limited. without any data, there is no
      # way to determine which key is in use or decrypt any data.
      #
      # this function simply throws an error if starting an decryption
      # while one is already in progress, and initializes the internal
      # buffer

      raise 'Decryption is not ready' unless @decryption_ready

      raise 'Decryption Already Started' if @decryption_started

      raise 'Decryption already in progress' if @key.present? && @key.key?('dec')

      @decryption_started = true
      @data = ''
    end

    def update(data)
      # Decryption of cipher text is performed here
      # Cipher text must be passed to this function in the order in which
      # it was output from the encryption.update function.

      # Each encryption has a header on it that identifies the algorithm
      # used  and an encryption of the data key that was used to encrypt
      # the original plain text. there is no guarantee how much of that
      # data will be passed to this function or how many times this
      # function will be called to process all of the data. to that end,
      # this function buffers data internally, when it is unable to
      # process it.
      #
      # The function buffers data internally until the entire header is
      # received. once the header has been received, the encrypted data
      # key is sent to the server for decryption. after the header has
      # been successfully handled, this function always decrypts all of
      # the data in its internal buffer *except* for however many bytes
      # are specified by the algorithm's tag size. see the end() function
      # for details.

      raise 'Decryption is not Started' unless @decryption_started

      # Append the incoming data in the internal data buffer
      @data += data

      # if there is no key or 'dec' member of key, then the code is
      # still trying to build a complete header
      if !@key.present? || !@key.key?('dec')
        struct_length = [1, 1, 1, 1, 1].pack('CCCCn').length
        packed_struct = @data[0...struct_length]

        # Does the buffer contain enough of the header to
        # determine the lengths of the initialization vector
        # and the key?
        if @data.length > struct_length
          # Unpack the values packed in encryption
          version, flags, algorithm_id, iv_length, key_length = packed_struct.unpack('CCCCn')

          # verify flag are correct and version is 0
          raise 'invalid encryption header' if (version != 0 ) || ((flags & ~Algo::UBIQ_HEADER_V0_FLAG_AAD) != 0)

          # Does the buffer contain the entire header?
          if @data.length > struct_length + iv_length + key_length
            # Extract the initialization vector
            iv = @data[struct_length...iv_length + struct_length]
            # Extract the encryped key
            encrypted_key = @data[struct_length + iv_length...key_length + struct_length + iv_length]
            # Remove the header from the buffer
            @data = @data[struct_length + iv_length + key_length..-1]

            # generate a local identifier for the key
            hash_sha512 = OpenSSL::Digest::SHA512.new
            hash_sha512 << encrypted_key
            client_id = hash_sha512.digest

            if @key.present?
              close if @key['client_id'] != client_id
            end

            # IF key object not exists, request a new one from the server
            unless @key.present?
              url = endpoint_base + '/decryption/key'
              query = { encrypted_data_key: Base64.strict_encode64(encrypted_key) }
              headers = Auth.build_headers(@papi, @sapi, endpoint, query, @host, 'post')

              response = HTTParty.post(
                url,
                body: query.to_json,
                headers: headers
              )

              # Response status is 200 OK
              if response.code == WEBrick::HTTPStatus::RC_OK
                @key = {}
                @key['finger_print'] = response['key_fingerprint']
                @key['client_id'] = client_id
                @key['session'] = response['encryption_session']

                # Get the algorithm name from the internal algorithm id in the header
                @key['algorithm'] = Algo.new.find_alg(algorithm_id)

                encrypted_private_key = response['encrypted_private_key']
                # Decrypt the encryped private key using SRSA
                private_key = OpenSSL::PKey::RSA.new(encrypted_private_key, @srsa)

                wrapped_data_key = response['wrapped_data_key']
                # Decode WDK from base64 format
                wdk = Base64.strict_decode64(wrapped_data_key)
                # Use private key to decrypt the wrapped data key
                dk = private_key.private_decrypt(wdk, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)

                @key['raw'] = dk
                @key['uses'] = 0
              else
                # Raise the error if response is not 200
                raise "HTTPError Response: Expected 201, got #{response.code}"
              end
            end

            # If the key object exists, create a new decryptor
            # with the initialization vector from the header and
            # the decrypted key (which is either new from the
            # server or cached from the previous decryption). in
            # either case, increment the key usage

            if @key.present?
              @algo = Algo.new.get_algo(@key['algorithm'])
              @key['dec'] = Algo.new.decryptor(@algo, @key['raw'], iv)
              # Documentation indicates the auth_data has to be set AFTER auth_tag
              # but we get an OpenSSL error when it is set AFTER an update call.
              # Checking OpenSSL documentation, there is not a requirement to set
              # auth_data before auth_tag so Ruby documentation seems to be
              # wrong.  This approach works and is compatible with the encrypted
              # data produced by the other languages' client library
              if (flags & Algo::UBIQ_HEADER_V0_FLAG_AAD) != 0
                 @key['dec'].auth_data = packed_struct + iv + encrypted_key
              end
              @key['uses'] += 1
            end
          end
        end
      end

      # if the object has a key and a decryptor, then decrypt whatever
      # data is in the buffer, less any data that needs to be saved to
      # serve as the tag.
      plain_text = ''
      if @key.present? && @key.key?('dec')
        size = @data.length - @algo[:tag_length]
        if size.positive?
          plain_text = @key['dec'].update(@data[0..size - 1])
          @data = @data[size..-1]
        end
        return plain_text
      end
    end

    def end
      raise 'Decryption is not Started' unless @decryption_started

      # The update function always maintains tag-size bytes in
      # the buffer because this function provides no data parameter.
      # by the time the caller calls this function, all data must
      # have already been input to the decryption object.

      sz = @data.length - @algo[:tag_length]

      raise 'Invalid Tag!' if sz.negative?

      if sz.zero?
        @key['dec'].auth_tag = @data
        begin
          pt = @key['dec'].final
          # Delete the decryptor context
          @key.delete('dec')
          # Return the decrypted plain data
          @decryption_started = false
          return pt
        rescue Exception
          print 'Invalid cipher data or tag!'
          return ''
        end
      end
    end

    def close
      raise 'Decryption currently running' if @decryption_started

      # Reset the internal state of the decryption object
      if @key.present?
        if @key['uses'].positive?
          query_url = "#{endpoint}/#{@key['finger_print']}/#{@key['session']}"
          url = "#{endpoint_base}/decryption/key/#{@key['finger_print']}/#{@key['session']}"
          query = { uses: @key['uses'] }
          headers = Auth.build_headers(@papi, @sapi, query_url, query, @host, 'patch')
          response = HTTParty.patch(
            url,
            body: query.to_json,
            headers: headers
          )
          remove_instance_variable(:@data)
          remove_instance_variable(:@key)
        end
      end
    end
  end

  def decrypt(creds, data)
    begin
      dec = Decryption.new(creds)
      res = dec.begin + dec.update(data) + dec.end
      dec.close
    rescue StandardError
      dec&.close
      raise
    end
    return res
  end
end
