require 'rb-readline'
require 'optparse'
require 'active_support/all'
require 'configparser'
require 'pathname'

# Sample application for using the Ubiq Platform to encrypt and decrypt data using
# both the Simple and Piecewise APIs.

require 'ubiq-security'

include Ubiq

# Build the Arguments hash values
class ArgumentParser
  def self.parse(args)
    options = {}

    opts = OptionParser.new do |opts|
      opts.on('-h', '--help', 'Show this help message and exit') do |_val|
        puts opts.help()
        exit
      end

      opts.on('-V', '--version', 'Show program\'s version number and exit') do |_val|
        puts 'ubiq-ruby/1.0.0'
        exit
      end

      # -e stands for encryption method
      opts.on('-e', 'Encrypt the contents of the input file and write the results to the output file') do |_val|
        options[:method] = 'encrypt'
      end

      # -d stands for decryption method
      opts.on('-d', 'Decrypt the contents of the input file and write the results to the output file') do |_val|
        options[:method] = 'decrypt'
      end

      # -s stands for simple method
      opts.on('-s', 'Use the simple encryption / decryption interfaces') do |_val|
        options[:mode] = 'simple'
      end

      # -p stands for piecewise method
      opts.on('-p', 'Use the piecewise encryption / decryption interfaces') do |_val|
        options[:mode] = 'piecewise'
      end

      # Value followed by -i or --infile flag will contain file name of input file
      opts.on('-i', '--infile INFILE', 'The input file containing the data to be encrypted/decrypted') do |val|
        options[:infile] = val
      end

      # Value followed by -o or --outfile flag will contain file name of output file
      opts.on('-o', '--outfile OUTFILE', 'The output file containing the result after encryption/decryption') do |val|
        options[:outfile] = val
      end

      # Value followed by -c or --credentials flag will contain file name of credentials file
      opts.on('-c', '--credentials CREDENTIALS', 'The name of the credentials file from where keys will be loaded') do |val|
        options[:credentials_file] = val
      end

      # -P stands for Profile
      opts.on('-P', '--profile PROFILE', 'identify the profile within the credentials file (default: default)') do |val|
        options[:profile] = val
      end
    end

    opts.parse(args)
    options
  end
end

# Set the chunk size ( 1 MB ) for piecewise encrypt/decrypt
CHUNK_SIZE = 1024 * 1024

def simple_encryption(credentials, infile, outfile)
  data = infile.read

  begin
    result = encrypt(
      credentials,
      data
    )
  rescue Exception => e
    print e
  end

  outfile.write(result)
end

def simple_decryption(credentials, infile, outfile)
  data = infile.read
  begin
    result = decrypt(
      credentials,
      data
    )
  rescue Exception => e
    print e
  end
  # Open the output file or Create if it does not exists
  outfile.write(result)
end

def piecewise_encryption(credentials, infile, outfile)
  enc = Encryption.new(
    credentials,
    1
  )

  begin
    outfile.write(enc.begin)
    # Loop through the file
    until infile.eof?
      chunk = infile.read CHUNK_SIZE
      outfile.write(enc.update(chunk))
    end
    outfile.write(enc.end)
    # Reset the encryption object to initial state and cleanup the memory in use
    enc.close
  rescue Exception => e
    print e
    enc&.close
  end
end

def piecewise_decryption(credentials, infile, outfile)
  dec = Decryption.new(
    credentials
  )
  begin
    outfile.write(dec.begin)
    # Loop through the file
    until infile.eof?
      chunk = infile.read CHUNK_SIZE
      outfile.write(dec.update(chunk))
    end
    outfile.write(dec.end)
    # Reset the decryption object to initial state and cleanup the memory in use
    dec.close
  rescue Exception => e
    print e
    dec&.close
  end
end

def load_credentials(filename)
  ConfigParser.new(filename)
end

def load_infile(filename)
  File.open(filename).size
end

# Define the max file size, if file size exceeds this, automatically piecewise method will be used
MAX_SIZE = 50 * 1025 * 1024

options = ArgumentParser.parse(ARGV)

# Raise error if Input file is not found by name given or is not readable
if options[:infile]
  unless File.exist?(options[:infile]) || File.readable?(options[:infile])
    raise "Unable to open input file #{options[:infile]} for reading. Check path or access rights."
  end
end

# Test if the user has access to the output file
# Raise error if Output file is present but now writable
if options[:outfile] && File.exist?(options[:outfile])
  raise 'Output file is not writable' unless File.writable?(options[:outfile])
end

creds = ConfigCredentials.new(options[:credentials_file], options[:profile]).get_attributes

# Calculate the file size of the input file
file_size = load_infile(options[:infile])

# If file size exceeds max size, set method to piecewise by default
if file_size > MAX_SIZE && options[:mode] != ('piecewise')
  puts 'NOTE: This is only for demonstration purposes and is designed to work on memory constrained devices.' \
    'Therefore, this sample application will switch to the piecewise APIs for files larger ' \
    "than #{MAX_SIZE} bytes in order to reduce excessive resource usages on resource constrained IoT devices"

  options[:mode] = 'piecewise'
end

# Open the input and output files once, if validated successfully
infile = File.open(options[:infile], 'rb')
outfile = File.open(options[:outfile], 'wb') # Opens or create a new one if does not exists

if options[:method]
  if options[:method] == 'encrypt'
    if options[:mode] == 'simple'
      simple_encryption(creds, infile, outfile)
    else
      piecewise_encryption(creds, infile, outfile)
    end

  elsif options[:method] == 'decrypt'
    if options[:mode] == 'simple'
      simple_decryption(creds, infile, outfile)
    else
      piecewise_decryption(creds, infile, outfile)
    end
  end
end

infile.close unless infile.closed?
outfile.close unless outfile.closed?
