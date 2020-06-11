'''
Cody Clark
30010560
CPSC418
Assignment 1

This program takes as arguments the filename of a file encrypted with
AES128, with a hash provided by the insecure SHA1.

It then guesses at the password which is known to be of the form
YYYYMMDD, with the year starting no later than 1984.

It then hashes that password and uses it as the key for AES.

The AES IV is found by examining the first 16 bytes of the submitted file.

After decrypting the ciphertext unpads the message then searches for the byte string
"FOXHOUND" in the plaintext. If found, it is now confirmed that
the password was correct, so it displays that to the screen.

After finding FOXHOUND it will see if CODE-RED appears and also trim
the hash tag t from the plaintext.

If it does not find CODE-RED, it will exit the program. If however CODE-RED does
appear it will modify the plaintext so that CODE-RED is changed to
CODE-BLUE, then it will write out the newly modified plaintext to
a file called "blueFile".

Usage: python3 modifyFile.py [ciphertext-filename]
'''

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
import os
import sys

# Bob sample password is 20100522

def trypass(iv, contents):
	b = default_backend()

	# Construct the passwords to test
	for y in range(1984, 2021):
		date = str(y)
		for m in range(1, 13):
			date = date[:4]
			if m < 10:
				date += '0' + str(m)
			else:
				date += str(m)
			for d in range(1, 32):
				date = date[:6]
				if d < 10:
					date += '0' + str(d)
				else:
					date += str(d)

				# Apply the SHA1 hash to the date and truncate it
				digest = hashes.Hash(hashes.SHA1(), backend = b)
				digest.update(bytes(date, 'utf-8'))
				digest = digest.finalize()
				key = digest[:16] # Truncate the key

				try:
					# Try the password
					cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = b)
					decryptor = cipher.decryptor()
					padded_msg = decryptor.update(contents) + decryptor.finalize()
					unpadder = padding.PKCS7(128).unpadder()
					msg = unpadder.update(padded_msg)
					msg = msg + unpadder.finalize()

					# If the password worked, we should find "FOXHOUND" within the message
					if msg.find(b"FOXHOUND") > 0:
						print("Password: " + date) # The password was correct, print the password
						#print(msg[:-20])
						msg = msg[:-20] # Truncates the cleartext by removing the hash tag t
						# print(msg)
						# Now check if CODE-RED is present
						# If it is then we must create a new file with modified cleartext
						# If not, then we can exit the program
						if msg.find(b"CODE-RED") > 0:

							# Modify the plaintext so it says "CODE-BLUE" and save it
							msg = msg.replace(b"CODE-RED", b"CODE-BLUE")
							with open("blueFile", "wb") as new_file_object:
								new_file_object.write(msg)
							return()
						else:
							return()
				except:
					continue

def main():

	# Open Bob's file for reading
	with open(sys.argv[1], "rb") as file_object:
		# Read the iv bytes from the file
		iv = file_object.read(16)

		# Then read the rest of the file
		contents = file_object.read()

		trypass(iv, contents)

main()
