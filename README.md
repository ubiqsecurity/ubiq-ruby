# Ubiq Security Ruby Library

The Ubiq Security Ruby library provides convenient interaction with the
Ubiq Security Platform API from applications written in the Ruby language.
It includes a pre-defined set of classes that will provide simple interfaces
to encrypt and decrypt data

## Documentation

See the [Ruby API docs][apidocs].



## Installation


To install using [Bundler][bundler] add the following to your project's Gemfile

```ruby
gem ubiq-security
```

To manually install `ubiq-security` via [Rubygems][rubygems] simply use gem to install it:

```sh
gem install ubiq-security
```

To build and install directly from a clone of the gitlab repository source:

```sh
git clone https://gitlab.com/ubiqsecurity/ubiq-ruby.git
cd ubiq-ruby
rake install:local
```


## Usage

The library needs to be configured with your account credentials which is
available in your [Ubiq Dashboard][dashboard] [Credentials][credentials].   The credentials can be 
explicitly set, set using environment variables, loaded from an explicit file
or read from the default location [~/.ubiq/credentials]

```ruby
require 'ubiq-security'
include Ubiq
```

### Read credentials from a specific file and use a specific profile 
```ruby
credentials = ConfigCredentials.new( "some-credential-file", "some-profile").get_attributes
```


### Read credentials from ~/.ubiq/credentials and use the default profile
```ruby
credentials = ConfigCredentials.new().get_attributes
```


### Use the following environment variables to set the credential values
UBIQ_ACCESS_KEY_ID  
UBIQ_SECRET_SIGNING_KEY  
UBIQ_SECRET_CRYPTO_ACCESS_KEY  
```ruby
credentials = Credentials()
```


### Explicitly set the credentials
```ruby
credentials = Credentials(access_key_id = "...", secret_signing_key = "...", secret_crypto_access_key = "...")
```




### Encrypt a simple block of data

Pass credentials and data into the encryption function.  The encrypted data will be returned.


```ruby
require 'ubiq-security'
include Ubiq

encrypted_data = encrypt(credentials, plaintext_data)
```


### Decrypt a simple block of data

Pass credentials and encrypted data into the decryption function.  The plaintext data will be returned.

```ruby
require 'ubiq-security'
include Ubiq

plaintext_data = decrypt(credentials, encrypted_data)
```


### Encrypt a large data element where data is loaded in chunks

- Create an encryption object using the credentials.
- Call the encryption instance begin method
- Call the encryption instance update method repeatedly until all the data is processed
- Call the encryption instance end method
- Call the encryption instance close method


```ruby
require 'ubiq-security'
include Ubiq

# Process 1 MiB of plaintext data at a time
BLOCK_SIZE = 1024 * 1024

# Rest of the program
....
   encryption = Encryption.new(credentials, 1)

   # Write out the header information
   encrypted_data = encryption.begin()
    
   # Loop until the end of the input file is reached
    until infile.eof?
      chunk = infile.read BLOCK_SIZE
      encrypted_data += encryption.update(chunk))
    end
    # Make sure any additional encrypted data is retrieved from encryption instance
    encrypted_data += encryption.end()
   
    # Make sure to release any resources used during the encryption process
    encryption.close()
```

### Decrypt a large data element where data is loaded in chunks

- Create an instance of the decryption object using the credentials.
- Call the decryption instance begin method
- Call the decryption instance update method repeatedly until all the data is processed
- Call the decryption instance end method
- Call the decryption instance close method


```ruby
require 'ubiq-security'
include Ubiq

# Process 1 MiB of encrypted data at a time
BLOCK_SIZE = 1024 * 1024

# Rest of the program
....

    decryption = Decryption(credentials)

    # Start the decryption and get any header information
    plaintext_data = decryption.begin())

    # Loop until the end of the input file is reached
    until infile.eof?
      chunk = infile.read BLOCK_SIZE
      plaintext_data += decryption.update(chunk)
    end
    
    # Make sure an additional plaintext data is retrieved from decryption instance
    plaintext_data += decryption.end()
    
    # Make sure to release any resources used during the decryption process
    decryption.close()
```




[bundler]: https://bundler.io
[rubygems]: https://rubygems.org
[gem]: https://rubygems.org/gems/uniq-security
[dashboard]:https://dev.ubiqsecurity.com/docs/dashboard
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
[apidocs]:https://dev.ubiqsecurity.com/docs/api


