# Cody Clark
# 30010560
# Last edit: April 19, 2020
# Client.py
#!/usr/bin/env python3

import socket
import sys
import os
import time
import secrets
import math
from math import sqrt, gcd
from sympy import isprime, primerange
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
HOST = '127.0.4.18'  # The server's hostname or IP address. Local = 127.0.0.1, A3 = 127.0.4.18
PORT = 31802        # Port to listen on (non-privileged ports are > 1023)

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
			
# Encrypts a message m
def RSAEncrypt(m, e, N):
	return pow(m, e, N)
	
# Decrypts a ciphertext c
def RSADecrypt(c, d, N):
	return pow(c, d, N)
	
	
# Generates an RSA signature
def RSASigGen(name, pk, d, N):
	# Compute H(t||t') where t = name || public_key
	digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
	digest.update(name + pk)
	t = digest.finalize()		
	digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
	digest.update(t)
	tp = digest.finalize()
				
	# Interpret H(t||t') as an integer
	tf = int.from_bytes((t + tp), 'big')
	tf = tf % N
				
	# Compute the RSA signature on tf ('decrypt' it)
	return RSADecrypt(tf, d, N)
	
			
##### MAIN #####
			

def main():
	print("TTP Starting...")
	# Establish the necessary cryptographic keys and key values
	TTP_p, TTP_q, TTP_N, TTP_e, TTP_d = RSAKeyGen()
	print("TTP: TTP_p = {0}".format(TTP_p))
	print("TTP: TTP_q = {0}".format(TTP_q))
	print("TTP: TTP_N = {0}".format(TTP_N))
	print("TTP: TTP_e = {0}".format(TTP_e))
	print("TTP: TTP_d = {0}".format(TTP_d))
	
	
	##### LIST FOR INCOMING CLIENT CONNECTIONS #####
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv:
		# Bind a socket
		serv.bind((HOST, PORT))
		r = ""
		
		# This server will run and listen for more connections until it receives "REQUEST KEY"
		while r != "REQUEST KEY":
			# listen allows the server to accept connections.
			serv.listen()
			print("TTP: TTP server listening for client connections...")

			# accept blocks and waits for an incoming connection. When a client connects,
			# it returns a new socket object representing the connection, and a tuple holding the client's address
			conn, addr = serv.accept()
			print("TTP: Client connected from ({0}, {1})".format(addr, conn))

			# Receive instruction from client
			with conn:
				for i in range(12):
					if r == "REQUEST KEY":
						break
					r = r + conn.recv(1).decode('utf-8')
				
				print("TTP: Receiving '{0}'".format(r))
			
				# A client wishes to receive a TTS signature
				if r == "REQUEST SIGN":
					# Receive the necessary values needed to generate a certificate
					namelength = conn.recv(4)						# Length of the name in bytes
					namelength = int.from_bytes(namelength, 'big')
					print("TTP: Receiving len(S) = {0}".format(namelength))
					name = conn.recv(namelength) 					# Byte array of the name
					name = name.decode('utf-8')
					print("TTP: Receiving S = '{0}'".format(name))
					Server_N = conn.recv(128)
					Server_N = int.from_bytes(Server_N, 'big')
					print("TTP: Receiving Server_N = {0}".format(Server_N))
					Server_e = conn.recv(128)
					Server_e = int.from_bytes(Server_e, 'big')
					print("TTP: Receiving Server_e = {0}".format(Server_e))
					Server_PK = Server_N.to_bytes(128, 'big') + Server_e.to_bytes(128, 'big') # Server RSA public key = N||e
					
					print("TTP: S = '{0}'".format(name))
					print("TTP: Server_N = {0}".format(Server_N))
					print("TTP: Server_e = {0}".format(Server_e))
					print("TTP: TTP_N = {0}".format(TTP_N))
					print("TTP: TTP_d = {0}".format(TTP_d))
				
					TTP_SIG = RSASigGen(name.encode('utf-8'), Server_PK, TTP_d, TTP_N) # Generate an RSA signature
					print("TTP: TTP_SIG = {0}".format(TTP_SIG))
				
					# Send N || S
					response = TTP_N.to_bytes(128, 'big') + TTP_SIG.to_bytes(128, 'big')
					print("TTP: Sending TTP_N = <{0}>".format(TTP_N.to_bytes(128, 'big').hex()))
					print("TTP: Sending TTP_SIG = <{0}>".format(TTP_SIG.to_bytes(128, 'big').hex()))
					conn.send(response) # Send the signature and N
					r = ""
				
				elif r == "REQUEST KEY":
					# Send N || e
					response = TTP_N.to_bytes(128, 'big') + TTP_e.to_bytes(128, 'big')
					print("TTP: Sending TTP_N = <{0}>".format(TTP_N.to_bytes(128, 'big').hex()))
					print("TTP: Sending TTP_e = <{0}>".format(TTP_N.to_bytes(128, 'big').hex()))
					conn.send(response)
				
				else:
					print("ERROR")
	
main()
