#!/usr/bin/python2.7
from os import urandom
import zlib
import argparse
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF
class IntegrityViolation(Exception):
        pass



def generate_keys(seed_text, salt):
    # Use the PBKDF2 algorithm to obtain the encryption and hmac key
    full_key = PBKDF2(seed_text, salt, dkLen=64, count=1345)

    # to encrypt the plain text log file. encrypt_key is 256 bits
    encrypt_key = full_key[:len(full_key) / 2]

    # Use the last half as the HMAC key
    hmac_key = full_key[len(full_key) / 2:]
    return encrypt_key, hmac_key


# this function writes the encrypted text to the file
def write_logfile(log_filename, auth_token, logfile_pt):
    # Compress the plaintext log file
    logfile_pt = zlib.compress(logfile_pt, 5)

    # Generate the encryption and hmac keys from the token,
    # using a random salt
    rand_salt = urandom(16)
    logfile_ct = rand_salt
    encrypt_key, hmac_key = generate_keys(auth_token, rand_salt)

    ctr_iv = urandom(16) # AES counter block is 128 bits (16 bytes)
    ctr = Counter.new(128, initial_value=long(ctr_iv.encode('hex'), 16))
    logfile_ct = logfile_ct + ctr_iv

    # Create the cipher object
    cipher = AES.new(encrypt_key, AES.MODE_CTR, counter=ctr)

    # Encrypt the plain text log and add it to the logfile cipher text
    logfile_ct = logfile_ct + cipher.encrypt(logfile_pt)

    # Use the 2nd half of the hashed token to sign the cipher text
    hmac_obj = HMAC.new(hmac_key, logfile_ct, SHA256)
    mac = hmac_obj.digest()

    # Add the mac to the encrypted log file
    logfile_ct = logfile_ct + mac

    # Write the signed and encrypted log file to disk
    with open(log_filename, 'wb') as f:
        f.write(logfile_ct)

    return None


# This function securely reads the log file from disk using
# authenticated encryption
def read_logfile(log_filename, auth_token):
    # Read in the encrypted log file. Caller should handle IO exception
    with open(log_filename, 'rb') as f:
        logfile_ct = f.read()

    # Extract the hmac salt from the file
    hmac_salt = logfile_ct[:16]

    # Generate the encryption and hmac keys from the token
    encrypt_key, hmac_key = generate_keys(auth_token, hmac_salt)

    # Set the mac_length
    mac_length = 32

    # Extract the MAC from the end of the file
    mac = logfile_ct[-mac_length:]

    # Cut the MAC off of the end of the ciphertext
    logfile_ct = logfile_ct[:-mac_length]

    # Check the MAC
    hmac_obj = HMAC.new(hmac_key, logfile_ct, SHA256)
    computed_mac = hmac_obj.digest()

    if computed_mac != mac:
        # The macs don't match. Raise an exception for the caller to handle.
        raise IntegrityViolation()

    # Cut the HMAC salt from the start of the file
    logfile_ct = logfile_ct[16:]

    # Recover the IV from the ciphertext
    ctr_iv = logfile_ct[:16]  # AES counter block is 128 bits (16 bytes)

    # Cut the IV off of the ciphertext
    logfile_ct = logfile_ct[16:]

    ctr = Counter.new(128, initial_value=long(ctr_iv.encode('hex'), 16))
    # Create the AES cipher object and decrypt the ciphertext
    cipher = AES.new(encrypt_key, AES.MODE_CTR, counter=ctr)
    logfile_pt = cipher.decrypt(logfile_ct)

    f.close()
    # Decompress the plain text log file
    logfile_pt = zlib.decompress(logfile_pt)
    with open(log_filename+'.dec', 'wb') as file:
        file.write(logfile_pt)


if __name__ == "__main__":


    parser = argparse.ArgumentParser(description='Decryption or Encryption of a file.')
    parser.add_argument('-f','--file', metavar='File', help='File To Process', required = True)
    parser.add_argument('-d', '--decrypt', nargs = '?', metavar='', default = 1, help='Decryption Mode')
    parser.add_argument('-e', '--encrypt', nargs = '?', metavar='', default = 1, help='Encryption Mode')
    parser.add_argument('-p', '--password', metavar='Password', required = True)
    args = parser.parse_args()

    filename = args.file

    token = args.password
    if args.decrypt == None:
        try:
            read_logfile(filename, token)
            print "File Successfully Decrypted And Saved To %s.dec"%filename
        except EnvironmentError:
            print "Error reading file from disk"
            raise SystemExit(5)
        except IntegrityViolation:
            print "Error authenticating the encrypted file"
            raise SystemExit(9)

    elif args.encrypt == None:
        try:
            with open(filename) as plain_text:
                write_logfile(filename, token, plain_text.read())
                print "File Successfully Encrypted"
        except EnvironmentError:
            # Includes IOError, OSError and WindowsError (if applicable)
            print "Error writing file to disk"
            raise SystemExit(5)
        except ValueError:
            print "ValueError exception raised"
            raise SystemExit(2)
    elif args.encrypt == args.decrypt:
        exit('You Need To Decrypt Or Encrypt')

