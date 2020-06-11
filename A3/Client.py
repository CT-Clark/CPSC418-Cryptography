# Cody Clark
# 30010560
# Last edit: April 19, 2020
# Client.py
#!/usr/bin/env python3

'''
	In this iteration of the assignment I am using HMAC
'''

# Client socket program
#import utilities
import socket
import sys, os
import secrets
import math
from math import gcd, sqrt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
#import sympy
HOST = '127.0.4.18'  # The server's hostname or IP address. Local = 127.0.0.1, A3 = 127.0.4.18
TTP_PORT = 31802        # The port used by the server, usually between 0 - 65535. Lower ports may be resrved
SERV_PORT = 31803

##### METHODS #####
# Encrypts a message m
def RSAEncrypt(m, e, N):
	return pow(m, e, N)
	
# Decrypts a ciphertext c
def RSADecrypt(c, d, N):
	return pow(c, d, N)
	
# Generates an RSA signature based on name||public key
# name and pk must be bytearrays, d and N must be integers
def RSASigGen(name, pk, d, N):
	# Compute H(t||t')
	digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
	digest.update(name + pk)
	t = digest.finalize()		
	digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
	digest.update(t)
	tp = digest.finalize()
				
	# Interpret H(t||t') as an integer
	tf = int.from_bytes((t + tp), 'big')
	tf = tf % N
				
	# Compute the RSA signature on tf
	return RSADecrypt(tf, d, N)
	
# Verifies an RSA signature given a name, public key, TTP's e and TTP's N
# name and pk must be bytearrays, TTP_e, TTP_N, and TTP_SIG must be integers
def RSASigVer(name, pk, TTP_e, TTP_N, TTP_SIG):
	# Compute H(t||t') where t = name || public_key 
	digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
	digest.update(name + pk)
	t = digest.finalize()		
	digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
	digest.update(t)
	tp = digest.finalize()
				
				
	tf = int.from_bytes((t + tp), 'big')
	tf = tf % TTP_N
	
	# Compute the RSA signature on TTP_SIG ('encrypt' it)
	servSIG = RSAEncrypt(TTP_SIG, TTP_e, TTP_N)
	##print("Signature M after encryption: ", servSIG)
	
	return tf == servSIG
	
	
##### MAIN #####	

def main():
	# Ask for username and password via standard input
	print("Input username: ", end='')
	sys.stdout.flush()
	uname = sys.stdin.readline()
	# encode it as bytes, and record the length
	unamebytes = uname.encode('utf-8')[:-1]
	# convert and store the length in a 4byte array in big-endian
	unamelength = len(unamebytes).to_bytes(4, 'big')
	print("Input password: ", end='')
	sys.stdout.flush()
	pword = sys.stdin.readline()
	# encode it as bytes, and record the length
	pwordbytes = pword.encode('utf-8')[:-1]
	#creates client string to be sent
	clientdata = unamelength + unamebytes 
	
	# Generate a random 16-byte salt, s
	s = 0
	while len(bin(s)[2:]) != (128):
		s = secrets.randbits(128)
	print("Client: s = <{0}>".format(s.to_bytes(16, 'big').hex()))
	
	# Compute a hash of the salt and password
	sp = s.to_bytes(16, 'big') + pwordbytes
	digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
	digest.update(sp)
	x = digest.finalize()
	x = int.from_bytes(x, 'big')
	print("Client: x = {0}".format(x))
	
	
	
	##### CONNECT TO TTP #####
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
		# Connect to TTP
		print("Client: Connecting to TTP...")
		conn.connect((HOST, TTP_PORT))
		print("Client: Connection successful.")
		
		# Request the key from TTP
		message = "REQUEST KEY".encode('utf-8')
		print("Client: Sending REQUEST KEY")
		conn.send(message)
		
		TTP_N = conn.recv(128)	# Receives TTS's modulo N
		TTP_N = int.from_bytes(TTP_N, 'big')
		print("Client: TTP_N = {0}".format(TTP_N))
		TTP_e = conn.recv(128)	# Receives TTS's public key e
		TTP_e = int.from_bytes(TTP_e, 'big')
		print("Client: TTP_e = {0}".format(TTP_e))

		print("Client: Closing connection to TTP...")
		conn.close()
		
		
		
	##### REGISTER WITH THE SERVER #####
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
		# Connect to server
		print("Client: Connecting to server...")
		conn.connect((HOST, SERV_PORT))
		print("Client: Connection successful. Now registering wih server.")
		
		##### REGISTER WITH SERVER #####
		# Receive N and g from the server
		Server_N = conn.recv(64)
		Server_N = int.from_bytes(Server_N, 'big')
		print("Client: Server_N = {0}".format(Server_N))
		Server_g = conn.recv(64)
		Server_g = int.from_bytes(Server_g, 'big')
		print("Client: Server_g = {0}".format(Server_g))
	
		# Compute v = g^x (mod N)
		v = pow(Server_g, x, Server_N)
		print("Client: v = {0}".format(v))
	
		# Client sends data to the server
		print("Client: Sending mode <{0}>".format('r'.encode('utf-8').hex()))
		print("Client: Sending len(username) <{0}>".format(len(unamebytes).to_bytes(4, 'big').hex()))
		print("Client: Sending username <{0}>".format(unamebytes.hex()))
		print("Client: Sending salt <{0}>".format(s.to_bytes(16, 'big').hex()))
		print("Client: Sending v <{0}>".format(v.to_bytes(64, 'big').hex()))
		conn.sendall('r'.encode('utf-8') + clientdata + s.to_bytes(16, 'big') + v.to_bytes(64,'big'))
	
		x = 0 # Disposing of x as per step 4
	
		print("Client: Registration successful. Closing Socket...")
	
		conn.shutdown(socket.SHUT_RDWR)
		conn.close()
		
		
		
	##### SRP PROTOCOL WITH THE SERVER #####
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
		# Connect to server
		print("Client: Connecting to server...")
		conn.connect((HOST, SERV_PORT))
		print("Client: Connection successful. Now registering wih server.")
		
		# Receive N and g from the server
		N = int.from_bytes(conn.recv(64), 'big')
		print("Client: N = {0}".format(N))
		g = int.from_bytes(conn.recv(64), 'big')
		print("Client: g = {0}".format(g))
	
		a = secrets.randbelow(N-1) # 1 <= a <= N-2 < N-1
		print("Client: a = {0}".format(a))

		A = pow(g, a, N)
		print("Client: A = {0}".format(A))
	
		# Client sends identification data to the server
		print("Client: Sending mode <{0}>".format('p'.encode('utf-8').hex()))
		print("Client: Sending len(username) <{0}>".format(len(unamebytes).to_bytes(4, 'big').hex()))
		print("Client: Sending username <{0}>".format(unamebytes.hex()))
		conn.sendall('p'.encode('utf-8') + len(unamebytes).to_bytes(4, 'big') + unamebytes)
    
		# Receive server name, RSA public key values, and signature data
		snamelength = conn.recv(4)
		snamelength = int.from_bytes(snamelength, 'big')
		print("Client: len(S) = {0}".format(snamelength))
		snamebytes = conn.recv(snamelength)
		print("Client: S = '{0}'".format(snamebytes.decode('utf-8').strip("\n")))
		Server_N = conn.recv(128)
		Server_N = int.from_bytes(Server_N, 'big')
		print("Client: Server_N = {0}".format(Server_N))
		Server_e = conn.recv(128)
		Server_e = int.from_bytes(Server_e, 'big')
		print("Client: Server_e = {0}".format(Server_e))
		Server_PK = Server_N.to_bytes(128, 'big') + Server_e.to_bytes(128, 'big')
		TTP_SIG = conn.recv(128)
		TTP_SIG = int.from_bytes(TTP_SIG, 'big')
		print("Client: TTP_SIG = {0}".format(TTP_SIG))
		
		# Now check if the server's name and public key match the TTS's signature of the server
		if RSASigVer(snamebytes, Server_PK, TTP_e, TTP_N, TTP_SIG): 
			# They match
			print("Client: Server signature verified")
				
			# Encrypt and then send Enc(A)
			EncA = pow(A, Server_e, Server_N)
			EncA = EncA.to_bytes(128, 'big')
			print("Client: Sending Enc(A) <{0}>".format(EncA.hex()))
			conn.send(EncA)
			
			# Client receives data from server
			Client_s = conn.recv(16)
			print("Client: Client_s = <{0}>".format(Client_s.hex()))
			Client_s = int.from_bytes(Client_s, 'big')
			B = conn.recv(64)
			B = int.from_bytes(B, 'big')
			print("Client: B = {0}".format(B))
	
			# Compute u = H(A||B) (mod N)
			digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
			digest.update(A.to_bytes(64, 'big') + B.to_bytes(64, 'big'))
			u = int.from_bytes(digest.finalize(), 'big') % N
			print("Client: u = {0}".format(u))
	
			# Compute client key = (B-kv)**(a+ux) (mod N)
			digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
			digest.update(sp)
			x = int.from_bytes(digest.finalize(), 'big')
	
			digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
			digest.update(N.to_bytes(64, 'big') + g.to_bytes(64, 'big'))
			k = int.from_bytes(digest.finalize(), 'big')
			print("Client: k = {0}".format(k))
	
			k_client = pow(int((B-int(k*v))), int((a+int(u*x))), N)
			print("Client: k_client = {0}".format(k_client))
	
			# Compute M1
			M1 = A.to_bytes(64, 'big') + B.to_bytes(64, 'big') + k_client.to_bytes(64, 'big')
			digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
			digest.update(M1)
			M1 = digest.finalize()
			print("Client: M1 = <{0}>".format(M1.hex()))
			print("Client: Sending M1 <{0}>".format(M1.hex()))
			conn.send(M1)
	
			# Receive M2 from server
			M2 = conn.recv(32)
			print("Client: M2 = <{0}>".format(M2.hex()))
	
			# Compute H(A||M1||k_client) and compare to M2
			M2c = A.to_bytes(64, 'big') + M1 + k_client.to_bytes(64, 'big')
			digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
			digest.update(M2c)
			M2c = digest.finalize()
	
			# Compare the calculated hash with the received hash
			if M2 == M2c:
				print("Client: Negotiation successful.")
			else:
				print("Client: Negotiation unsuccessful.")
				exit()
				
			
			##### SENDING FILE #####
			print("FILE SENDING AREA BE HERE")
			in_file = sys.argv[1]
			
			# Open the new file for reading (Step a)
			with open(in_file, "rb") as file_object:
				# Read the file contents
				contents = file_object.read()
				
			iv = os.urandom(16)
			print("Client: iv = <{0}>".format(iv.hex()))
				
			# Get a 256 hash of the key
			k_hash = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
			k_hash.update(k_client.to_bytes(64, 'big'))
			k_hash = k_hash.finalize()
			print("Client: key = <{0}>".format(k_hash.hex()))
			
			# Apply HMAC
			tag = hmac.HMAC(k_hash, hashes.SHA3_256(), backend=default_backend())
			tag.update(contents) # x = message to hash
			tag = tag.finalize()
			contents = contents + tag
			
			# Pad data
			padder = padding.PKCS7(128).padder()
			padded_data = padder.update(contents)
			padded_data += padder.finalize()
			
			# Set up our AES256 CBC encryption cipher
			cipher = Cipher(algorithms.AES(k_hash), modes.CBC(iv), default_backend())
			encryptor = cipher.encryptor()
			ciphertext = encryptor.update(padded_data) + encryptor.finalize()
			ciphertext = iv + ciphertext
			
			message = len(ciphertext).to_bytes(4, 'big') + ciphertext
			
			print("Client: Sending len(PTXT) <{0}>".format(len(ciphertext).to_bytes(4, 'big').hex()))
			conn.sendall(message)
			print("Client: File {0} sent.".format(in_file))
	
			conn.shutdown(socket.SHUT_RDWR)
			conn.close()
				
			
		else: 
			# They don't match
			print("Client: Server signature doesn't match.")
			exit()
	
main()
