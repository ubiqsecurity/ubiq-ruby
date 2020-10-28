# frozen_string_literal: true

require 'active_support/all'
require 'openssl'

module Ubiq
  # Class to provide some basic information mapping between an
  # encryption algorithm name and the cooresponding
  # key size, initialization vector length, and tag

  class Algo

    UBIQ_HEADER_V0_FLAG_AAD = 0b00000001

    def set_algo
      @algorithm = {
        'aes-256-gcm' => {
          id: 0,
          algorithm: OpenSSL::Cipher::AES256,
          mode: OpenSSL::Cipher::AES256.new(:GCM),
          key_length: 32,
          iv_length: 12,
          tag_length: 16
        },
        'aes-128-gcm' => {
          id: 1,
          algorithm: OpenSSL::Cipher::AES128,
          mode: OpenSSL::Cipher::AES128.new(:GCM),
          key_length: 16,
          iv_length: 12,
          tag_length: 16
        }
      }
    end

    def find_alg(id)
      set_algo.each do |k,v|
        if v[:id] == id
           return k
         end
      end
      "unknown"
    end

    def get_algo(name)
      set_algo[name]
    end

    def encryptor(obj, key, iv = nil)
      # key : A byte string containing the key to be used with this encryption
      # If the caller specifies the initialization vector, it must be
      # the correct length and, if so, will be used. If it is not
      # specified, the function will generate a new one

      raise RuntimeError, 'Invalid key length' if key.length != obj[:key_length]

      raise RuntimeError, 'Invalid initialization vector length' if !iv.nil? && iv.length != obj[:iv_length]

      cipher = obj[:mode]
      cipher.encrypt
      cipher.key = key
      iv = cipher.random_iv
      return cipher, iv
    end

    def decryptor(obj, key, iv)
      raise RuntimeError, 'Invalid key length' if key.length != obj[:key_length]

      raise RuntimeError, 'Invalid initialization vector length' if !iv.nil? && iv.length != obj[:iv_length]

      cipher = obj[:mode]
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv
      return cipher
    end
  end
end
