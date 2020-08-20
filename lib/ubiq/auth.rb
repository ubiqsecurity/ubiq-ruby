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

module Ubiq

class Auth
  # HTTP Authentication for the Ubiq Platform

  # This module implements HTTP authentication for the Ubiq platform
  # via message signing as described by the IETF httpbis-message-signatures
  # draft specification.

  def self.build_headers(papi, sapi, endpoint, query, host, http_method)

    # This function calculates the signature for the message, adding the Signature header
    # to contain the data. Certain HTTP headers are required for
    # signature calculation and will be added by this code as
    # necessary. The constructed headers object is returned

    # the '(request-target)' is part of the signed data.
    # it's value is 'http_method path?query'
    reqt = "#{http_method} #{endpoint}"

    # The time at which the signature was created expressed as the unix epoch
    created = Time.now.to_i

    # the Digest header is always included/overridden by
    # this code. it is a hash of the body of the http message
    # and is always present even if the body is empty
    hash_sha512 = OpenSSL::Digest::SHA512.new
    hash_sha512 << JSON.dump(query)
    digest = 'SHA-512='+Base64.strict_encode64(hash_sha512.digest)

    # Initialize the headers object to be returned via this method
    all_headers = {}
    # The content type of request
    all_headers['content-type'] = 'application/json'
    # The request target calculated above(reqt)
    all_headers['(request-target)'] = reqt
    # The date and time in GMT format
    all_headers['date'] = get_date
    # The host specified by the caller
    all_headers['host'] = get_host(host)
    all_headers['(created)'] = created
    all_headers['digest'] = digest
    headers = ['content-type', 'date', 'host', '(created)', '(request-target)', 'digest']

    # include the specified headers in the hmac calculation. each
    # header is of the form 'header_name: header value\n'
    # included headers are also added to an ordered list of headers
    # which is included in the message
    hmac = OpenSSL::HMAC.new(sapi, OpenSSL::Digest::SHA512.new)
    headers.each do |header|
      if all_headers.key?(header)
        hmac << "#{header}: #{all_headers[header]}\n"
      end
    end

    all_headers.delete('(created)')
    all_headers.delete('(request-target)')
    all_headers.delete('host')

    # Build the Signature header itself
    all_headers['signature']  = 'keyId="' + papi + '"'
    all_headers['signature'] += ', algorithm="hmac-sha512"'
    all_headers['signature'] += ', created=' + created.to_s
    all_headers['signature'] += ', headers="' + headers.join(" ") + '"'
    all_headers['signature'] += ', signature="'
    all_headers['signature'] += Base64.strict_encode64(hmac.digest)
    all_headers['signature'] += '"'

    return all_headers
  end

  def self.get_host(host)
    uri = URI(host)
    return "#{uri.hostname}:#{uri.port}"
  end

  def self.get_date
    DateTime.now.in_time_zone('GMT').strftime("%a, %d %b %Y") + " " + DateTime.now.in_time_zone('GMT').strftime("%H:%M:%S") + " GMT"
  end

end
end
