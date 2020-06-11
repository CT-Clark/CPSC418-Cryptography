# Cody Clark
# 30010560
# Last edit: April 19, 2020
# Client.py
#!/usr/bin/env python3

'''
	In this iteration of the assignment I am using HMAC
'''


import socket
import sys
import os
import time
import secrets
import math
from math import sqrt, gcd
from sympy import isprime, primerange
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
HOST = '127.0.4.18'  # The server's hostname or IP address. Local = 127.0.0.1, A3 = 127.0.4.18
TTP_PORT = 31802        # Port to listen on (non-privileged ports are > 1023)
CLIENT_PORT = 31803

##### METHODS #####

# Extended Euclidean Algorithm
def xgcd(a, b):
	x0, x1, y0, y1 = 0, 1, 1, 0
	while a != 0:
		(q, a), b = divmod(b, a), a
		y0, y1 = y1, y0 - q * y1
		x0, x1 = x1, x0 - q * x1
	return b, x0, y0

# Modular Inverse
def modinv(a, b):
	g, x, _ = xgcd(a, b)
	if g != 1:
		raise Exception('gcd(a, b) != !')
	return x % b

# Generates an RSA key pair
def RSAKeyGen():
	p = primeGen() # Generate a large safe prime p
	q = primeGen() # Generate a large safe prime q
	while p == q:  # Makes sure p != q
		q = primeGen()	
	N = p * q			# Calculate N
	phiN = (p-1)*(q-1)	# Calculate Euler's phi of N
	
	# Randomly choose a useable e
	e = secrets.randbelow(phiN)
	while math.gcd(phiN, e) != 1 or e < 3:	
		e = secrets.randbelow(phiN)
		
	# Calculate d such that ed (equiv) 1 (mod phi(N))
	d = modinv(e, phiN)
	
	return p, q, N, e, d
	
def primeGen():
	while True:
		q = secrets.randbits(511) # Generate a random 511 bit number
		
		# Before checking if it's prime make sure it actually is 511 bits
		if len(bin(q)[2:]) != 511:				
			continue
		# Before checking if q is prime, make it more efficient by removing obvious suspects
		if (q % 2 == 0) or (q % 3 == 0) or (q % 5 == 0) or (q % 7 == 0):
			continue
		if isprime(q):
			N = 2*q + 1
			if isprime(N):
				return N


# This method finds a prime root for some prime p
def primRoot(p):
	# Assemble a list of prime factors for p
	f = [2, int((p-1)//2)]
	
	# Find a small prime
	for q in primerange(2, int(sqrt(p))):		# Won't interate through all of those primes, likely very few
		mods = []
		for r in f:
			n = pow(q, int((p-1)//r), p)
			mods.append(n)
			
		for m in mods:
			if m == 1:
				break
			if m == mods[-1]:
				return q
				
				
##### MAIN #####

def main():
	# Name the server
	print("SERVER: Please enter a server name: ", end='')
	sys.stdout.flush()
	sname = sys.stdin.readline()
	snamebytes = sname.encode('utf-8')[:-1]
	snamelength = len(snamebytes)
	
	##### SRP SETUP #####
	# Generate a large prime and a primative root of that prime
	print("Server: Generating N and g")
	N = primeGen()
	print("Server: N = {0}".format(N))
	g = primRoot(N)
	print("Server: g = {0}".format(g))
	
	# Calculate k = H(N||g)
	digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
	digest.update(N.to_bytes(64, 'big') + g.to_bytes(64, 'big'))
	k = digest.finalize()
	print("Server: k = {0}".format(int.from_bytes(k, 'big')))
	
	##### RSA SETUP #####
	# Generate RSA key values
	print("Server: Generating RSA values")
	Server_p, Server_q, Server_N, Server_e, Server_d = RSAKeyGen()
	print("Server: Server_p = {0}".format(Server_p))
	print("Server: Server_q = {0}".format(Server_q))
	print("Server: Server_d = {0}".format(Server_d))
	print("Server: Server_e = {0}".format(Server_e))
	print("Server: Server_N = {0}".format(Server_N))
	
	# Server public key pair pk = (N, e)
	Server_PK = Server_N.to_bytes(128, 'big') + Server_e.to_bytes(128, 'big')

	##### CONNECT TO TTP #####
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
		#connect to TTP server
		conn.connect((HOST, TTP_PORT))
	
		# Send a signature request to the TTP server
		message = "REQUEST SIGN".encode('utf-8')
		print("Server: Sending REQUEST SIGN")
		conn.send(message)
		
		print("Server: Sending len(S) <{0}>".format(snamelength.to_bytes(4, 'big').hex()))
		print("Server: Sending S <{0}>".format(snamebytes.hex()))
		print("Server: Sending Server_N <{0}>".format(Server_N.to_bytes(128, 'big').hex()))
		print("Server: Sending Server_e <{0}>".format(Server_e.to_bytes(128, 'big').hex()))
		conn.send(snamelength.to_bytes(4, 'big') + snamebytes + Server_PK)
	
		# Receive the TTP public key values and requested signature
		TTP_N = conn.recv(128)
		TTP_N = int.from_bytes(TTP_N, 'big')
		print("Server: TTP_N = {0}".format(TTP_N))
		TTP_SIG = conn.recv(128)
		TTP_SIG = int.from_bytes(TTP_SIG, 'big')
		print("Server: TTP_SIG = {0}".format(TTP_SIG))
		print("Server: Closing connection.")
		conn.close()
	
	
	##### LISTEN FOR CLIENT #####
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv:
		
		# Bind a socket
		serv.bind((HOST, CLIENT_PORT))
		
		
		##### CLIENT REGISTRATION #####
		# listen allows the server to accept connections.
		serv.listen()
		print("Server: Server listening for client...")
		conn, addr = serv.accept()
		print("Server: Client connected from ({0}, {1})".format(addr, conn))

		with conn:
			##### CLIENT REGISTRATION #####
			print("Server: Sending N <{0}>".format(N.to_bytes(64, 'big').hex()))
			print("Server: Sending g <{0}>".format(g.to_bytes(64, 'big').hex()))
			conn.sendall((N.to_bytes(64, 'big') + g.to_bytes(64, 'big'))) # Send data to new client
        
			# Receive data from client
			mode = conn.recv(1)
			print("Server: mode = '{0}'".format(mode.decode('utf-8')))
			ilen = int.from_bytes(conn.recv(4), 'big')
			I = ((conn.recv(ilen)).decode('utf-8')).strip('\n')
			print("Server: I = '{0}'".format(I))
			s = int.from_bytes(conn.recv(16), 'big')
			print("Server: s = <{0}>".format(s.to_bytes(16, 'big').hex()))
			v = int.from_bytes(conn.recv(64), 'big')
			print("Server: v = {0}".format(v))
			print("Server: Registration successful.")
			
			
			
			
		##### CLIENT SRP PROTOCOL #####
		# Listen for the next connection by the server
		serv.listen()
		print("Server: Server listening for client...")
		conn, addr = serv.accept()
		print("Server: Client connected from ({0}, {1})".format(addr, conn))
		
		with conn:	
			print("Server: Sending N <{0}>".format(N.to_bytes(64, 'big').hex()))
			print("Server: Sending g <{0}>".format(g.to_bytes(64, 'big').hex()))
			conn.sendall(N.to_bytes(64, 'big') + g.to_bytes(64, 'big')) # Send data to new client
		
			# Receive data from client
			mode = conn.recv(1)
			print("Server: mode = {0}".format(mode.decode('utf-8')))
			ilen = int.from_bytes(conn.recv(4), 'big')
			I = ((conn.recv(ilen)).decode('utf-8')).strip('\n')
			print("Server: I = '{0}'".format(I))
			
			# Send data to the client for signature verification
			# Send server info and signature to the client
			print("Server: Sending len(S) <{0}>".format(snamelength.to_bytes(4, 'big').hex()))
			print("Server: Sending S <{0}>".format(snamebytes.hex()))
			print("Server: Sending Server_N <{0}>".format(Server_N.to_bytes(128, 'big').hex()))
			print("Server: Sending Server_e <{0}>".format(Server_e.to_bytes(128, 'big').hex()))
			print("Server: Sending TTP_SIG <{0}>".format(TTP_SIG.to_bytes(128, 'big').hex()))
			conn.sendall(snamelength.to_bytes(4, 'big') + snamebytes + Server_PK + TTP_SIG.to_bytes(128, 'big'))
			
			# Receive Enc(A) from the client
			EncA = int.from_bytes(conn.recv(128), 'big') # Enc(A) is mod N, therefore we know Enc(A) < 128 bytes
			print("Server: Enc(A) = {0}".format(EncA))
			
			# Decrypt Enc(A)
			A = pow(EncA, Server_d, Server_N)
			print("Server: A = {0}".format(A))
			
			# Check if A is congruent to 0 under N
			if A % N == 0:
				print("Server: Negotiation unsuccessful.")
				print("Closing program.")
				exit()
		
			# Calculate B
			print("Server: s = <{0}>".format(s.to_bytes(16, 'big').hex()))
			print("Server: v = {0}".format(v))
			b = secrets.randbelow(N-1) # 1 <= b <= N-2 < N-1
			print("Server: b = {0}".format(b))
			B = (pow(int.from_bytes(k, 'big')*v, 1, N) + pow(g, b, N)) % N
			print("Server: B = {0}".format(B))
			
			# Send salt s and B to client
			print("Server: Sending salt <{0}>".format(s.to_bytes(16, 'big').hex()))
			print("Server: Sending B <{0}>".format(B.to_bytes(64, 'big').hex()))
			conn.send(s.to_bytes(16, 'big') + B.to_bytes(64, 'big'))
		
			# Compute u = H(A||B) (mod N)
			digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
			digest.update(A.to_bytes(64, 'big') + B.to_bytes(64, 'big'))
			u = digest.finalize()
			u = int.from_bytes(u, 'big') % N
			print("Server: u = {0}".format(u))
		
			# Compute the server key = (Av**u)**b (mod N)
			k_server = pow(((A % N)*(pow(v, u, N))), b, N)
			print("Server: k_server = {0}".format(k_server))
		
			# Calculate the hash to compare to M1
			M1s = A.to_bytes(64, 'big') + B.to_bytes(64, 'big') + k_server.to_bytes(64, 'big')
			digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
			digest.update(M1s)
			M1s = digest.finalize()
			M1 = conn.recv(32)
			print("Server: M1 = <{0}>".format(M1.hex()))
			
			# Calculate M2 and then send it to the client
			M2 = A.to_bytes(64, 'big') + M1 + k_server.to_bytes(64, 'big')
			digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
			digest.update(M2)
			M2 = digest.finalize()
			print("Server:	M2 = <{0}>".format(M2.hex()))
			print("Server:	Sending M2 <{0}>".format(M2.hex()))
			conn.send(M2)
		
			#print("M1s: <{0}>".format(M1s.hex()))
			# Compare the calculated hash with the received hash
			if M1 == M1s:
				print("Server: Negotiation successful.")
			else:
				print("Server: Negotiation unsuccessful.")
				exit()
			
			
			##### FILE RECEIVING #####
			filelength = conn.recv(4) # Receive the length of the file
			iv = conn.recv(16) # Receive the iv
			print("Server: iv = <{0}>".format(iv.hex()))
			ciphertext = conn.recv(int.from_bytes(filelength, 'big')-16)
			
			# Hash the key
			k_hash = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
			k_hash.update(k_server.to_bytes(64, 'big'))
			k_hash = k_hash.finalize()
			print("Server: key = <{0}>".format(k_hash.hex()))
			
			decryptor = Cipher(algorithms.AES(k_hash), modes.CBC(iv), default_backend()).decryptor()
			padded_msg = decryptor.update(ciphertext) + decryptor.finalize()
			unpadder = padding.PKCS7(128).unpadder()
			msg = unpadder.update(padded_msg) + unpadder.finalize()
			
			plaintextlength = len(msg) - 32
			
			tag = msg[plaintextlength:]
			print("Server: tag = <{0}>".format(tag.hex()))
			plaintext = msg[:plaintextlength]
			#print("Server: plaintext = <{0}>".format(plaintext.hex()))
			
			# Check that the tag matches
			tagcheck = hmac.HMAC(k_hash, hashes.SHA3_256(), backend=default_backend())
			tagcheck.update(plaintext) # x = message to hash
			tagcheck = tagcheck.finalize()
			print("Server: tagcheck = <{0}>".format(tagcheck.hex()))
			
			if tag == tagcheck:
				# Write the unencrypted contents to the file specified in the command line
				out_file = sys.argv[1]
				with open(out_file, "wb") as new_file_object:
					new_file_object.write(plaintext)
			else:
				print("Server: HMAC tag does not match plaintext. Exiting.")

			# Shut down the server
			conn.shutdown(socket.SHUT_RDWR)
			conn.close()
			
			
main()
		
sys.exit(0)
