'''
Cody Clark
30010560
CPSC418
Assignment 1

This program takes a previously created plaintext and encrypts it using the
same AES, SHA1, and PKCS7 algorithms which Bob used. It also uses
any password, most likely the same one which Bob used initially for his
CODE-RED file, although a different password could be specified.

Usage: python3 encryptFile.py [plaintext-filename] [tampered-filename] [password]
'''

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
import os
import sys

def main():

	in_file = sys.argv[1]
	out_file = sys.argv[2]
	password = bytes(sys.argv[3].encode('utf-8'))
	contents = ''
	b = default_backend()

	# Open the new file for reading (Step a)
	with open(in_file, "rb") as file_object:
		# Read the iv bytes from the file
		contents = file_object.read()

	# Compute hash tag and append (Step b)
	hash_tag = hashes.Hash(hashes.SHA1(), backend = b)
	hash_tag.update(contents)
	hash_tag = hash_tag.finalize()
	contents += hash_tag

	# Apply SHA1 to date key for hash, then truncate (Step c)
	pass_hash = hashes.Hash(hashes.SHA1(), backend = b)
	pass_hash.update(password)
	pass_hash = pass_hash.finalize()
	key = pass_hash[:16]

	# Generate random IV (Step d)
	iv = os.urandom(16)

	# Open a new file for writing
	with open(out_file, "wb") as new_file_object:
		new_file_object.write(iv)

		# Pad data
		padder = padding.PKCS7(128).padder()
		padded_data = padder.update(contents)
		padded_data += padder.finalize()

		# Encrypt data
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = b)
		encryptor = cipher.encryptor()
		enc_data = encryptor.update(padded_data) + encryptor.finalize()

		new_file_object.write(enc_data)


main()
