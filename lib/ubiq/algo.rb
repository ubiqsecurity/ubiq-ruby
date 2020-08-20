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

require "active_support/all"
require 'openssl'

module Ubiq

class Algo

  def set_algo
    @algorithm = {
      "aes-256-gcm"=>{
        id:0,
        algorithm: OpenSSL::Cipher::AES256,
        mode: OpenSSL::Cipher::AES256.new(:GCM),
        key_length: 32,
        iv_length: 12,
        tag_length: 16
      },
    }
  end

  def get_algo(name)
    set_algo[name]
  end

  def encryptor(obj,key, iv=nil)
    # key : A byte string containing the key to be used with this encryption
    # If the caller specifies the initialization vector, it must be
    # the correct length and, if so, will be used. If it is not
    # specified, the function will generate a new one

    cipher = obj[:mode]
    raise RuntimeError, 'Invalid key length' if key.length != obj[:key_length]

    raise RuntimeError, 'Invalid initialization vector length' if (iv!= nil and iv.length != obj[:iv_length])
    cipher.encrypt
    cipher.key = key
    iv = cipher.random_iv
    return cipher, iv
  end

  def decryptor(obj, key, iv)
    cipher = obj[:mode]
    raise RuntimeError, 'Invalid key length' if key.length != obj[:key_length]

    raise RuntimeError, 'Invalid initialization vector length' if (iv!= nil and iv.length != obj[:iv_length])
    cipher = obj[:mode]
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv
    return cipher
  end
end
end
