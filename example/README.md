# Ubiq Security Sample Application using Ruby Library


This sample application will demonstrate how to encrypt and decrypt data using 
the different APIs.


### Documentation

See the [Ruby API docs][apidocs].

## Installation

From within the examples directory using [Bundler][bundler]

```bash
cd examples
bundler install
```
To manually install the ubiq-security library

```sh
gem install ubiq-security
```

## Credentials file

Edit the credentials file with your account [Credentials][credentials] created using the [Ubiq Dashboard][dashboard].

```sh
[default]
ACCESS_KEY_ID = ...
SECRET_SIGNING_KEY = ...
SECRET_CRYPTO_ACCESS_KEY = ...
```



## View Program Options

From within the examples directory using [Bundler][bundler]

```
cd examples
ruby ubiq_sample.rb -h
```
<pre>

Usage: ubiq_sample [options]
    -h, --help            Show this help message and exit
    -V, --version         Show program's version number and exit
    -e                    Encrypt the contents of the input file and write the results to output file
    -d                    Decrypt the contents of the input file and write the results to output file
    -s,                   Use the simple encryption / decryption interfaces
    -p,                   Use the piecewise encryption / decryption interfaces
    -i, --infile INFILE
                          The input file containing the data to be encrypted/decrypted
    -o, --outfile OUTFILE
                          The output file containing the result after encryption/decryption
    -c, --credentials CREDENTIALS
                          The name of the credentials file from where keys will be loaded
    -P, --profile PROFILE
    -P PROFILE, --profile PROFILE
                          Identify the profile within the credentials file (default: default)
</pre>

#### Demonstrate using the simple (-s / --simple) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
ruby ubiq_sample.rb -i ./README.md -o /tmp/readme.enc -e -s -c ./credentials 
```

#### Demonstrate using the simple (-s / --simple) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
ruby ubiq_sample.rb -i /tmp/readme.enc -o /tmp/README.out -d -s -c ./credentials
```

#### Demonstrate using the piecewise (-p / --piecewise) API interface to encrypt this README.md file and write the encrypted data to /tmp/readme.enc

```sh
ruby ubiq_sample.rb -i ./README.md -o /tmp/readme.enc -e -p -c ./credentials
```

#### Demonstrate using the piecewise (-p / --piecewise) API interface to decrypt the /tmp/readme.enc file and write the decrypted output to /tmp/README.out

```sh
ruby ubiq_sample.rb -i /tmp/readme.enc -o /tmp/README.out -d -p -c ./credentials
```

[bundler]: https://bundler.io
[rubygems]: https://rubygems.org
[dashboard]:https://dev.ubiqsecurity.com/docs/dashboard
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
[apidocs]:https://dev.ubiqsecurity.com/docs/api
