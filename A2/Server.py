# Cody Clark
# 30010560
# Server.py
#!/usr/bin/env python3
import socket
import sys
import os
import time
import secrets
from math import sqrt
from sympy import isprime, primerange
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
HOST = '127.0.4.18'  # Standard loopback interface address (localhost) (Change to 127.0.4.18 for autograder)
PORT = 31802        # Port to listen on (non-privileged ports are > 1023)

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

# Generate a random 512-bit safe prime
def genPrime():
	prime = False
	while prime != True:
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
				prime = True
				return N

# Generate a large prime
N = genPrime()
print("Server: N = {0}".format(N))
sys.stdout.flush()
# Find a primitive root g of N
g = primRoot(N)
print("Server: g = {0}".format(g))
sys.stdout.flush()

# Calculate k = H(N||g)
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(N.to_bytes(64, 'big') + g.to_bytes(64, 'big'))
k = digest.finalize()
print("Server: k = <{0}>".format(k.hex()))
sys.stdout.flush()

# socket.socket() creates a socket object
# socket objects support the context manager type, this means we can use the 'with' statement
# the two arguments to to socket() specify the address family and socket type:
#   AF_INET is the internet address family for IPv4: indicates the
#   SOCK_STREAM is the socket type ofr TCP, the protocol that will be used to transport messages on the network
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv:

	# Bind a socket
	serv.bind((HOST, PORT))
	print('Server listening...')
	sys.stdout.flush()

	# listen allows the server to accept connections.
	serv.listen()

	# accept blocks and waits for an incoming connection. When a client connects,
	# it returns a new socket object representing the connection, and a tuple holding the client's address
	conn, addr = serv.accept()

	# Register the client
	with conn:
		print("Server: Sending N <{0}>".format(N.to_bytes(64, 'big').hex()))
		sys.stdout.flush()
		print("Server: Sending g <{0}>".format(g.to_bytes(64, 'big').hex()))
		sys.stdout.flush()
		conn.sendall((N.to_bytes(64, 'big') + g.to_bytes(64, 'big'))) # Send data to new client
        
		# Receive data from client
		r = conn.recv(1)
		print("Server: r = {0}".format(r.decode('utf-8')))
		sys.stdout.flush()
		ilen = int.from_bytes(conn.recv(4), 'big')
		print("Server: |I| = <{0}>".format(ilen.to_bytes(4, 'big').hex()))
		sys.stdout.flush()
		I = ((conn.recv(ilen)).decode('utf-8')).strip('\n')
		print("Server: I = {0}".format(I))
		sys.stdout.flush()
		s = int.from_bytes(conn.recv(16), 'big')
		print("Server: s = <{0}>".format(s.to_bytes(16, 'big').hex()))
		sys.stdout.flush()
		v = int.from_bytes(conn.recv(64), 'big')
		print("Server: v = {0}".format(v))
		sys.stdout.flush()
		
		print("Server: 'Registration successful.'")
		sys.stdout.flush()
		
		sys.stdout.flush()
		
#----------#----------#----------#----------#
		
	# Listen for the next connection by the server
	serv.listen()
    
	conn, addr = serv.accept()

	## conn is a new socket which is used to communicate with the client
	with conn:	
		print("Server: Sending N <{0}>".format(N.to_bytes(64, 'big').hex()))
		sys.stdout.flush()
		print("Server: Sending g <{0}>".format(g.to_bytes(64, 'big').hex()))
		sys.stdout.flush()
		conn.sendall(N.to_bytes(64, 'big') + g.to_bytes(64, 'big')) # Send data to new client
		
		# Receive data from client
		p = conn.recv(1)
		print("Server: p = {0}".format(p.decode('utf-8')))
		sys.stdout.flush()
		ilen = int.from_bytes(conn.recv(4), 'big')
		print("Server: |I| = <{0}>".format(ilen.to_bytes(4, 'big').hex()))
		sys.stdout.flush()
		I = ((conn.recv(ilen)).decode('utf-8')).strip('\n')
		print("Server: I = {0}".format(I))
		sys.stdout.flush()
		A = int.from_bytes(conn.recv(64), 'big')
		print("Server: A = {0}".format(A))
		sys.stdout.flush()
		
		# Calculate B
		b = secrets.randbelow(N-1) # 1 <= b <= N-2 < N-1
		print("Server: b = {0}".format(b))
		sys.stdout.flush()
		B = (pow(int.from_bytes(k, 'big')*v, 1, N) + pow(g, b, N)) % N
		print("Server: B = {0}".format(B))
		sys.stdout.flush()
		
		# Send salt s and B to client
		print("Server: Sending s <{0}>".format(s.to_bytes(16, 'big').hex()))
		sys.stdout.flush()
		print("Server: Sending B <{0}>".format(B.to_bytes(64, 'big').hex()))
		sys.stdout.flush()
		conn.send(s.to_bytes(16, 'big') + B.to_bytes(64, 'big'))
		
		# Compute u = H(A||B) (mod N)
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(A.to_bytes(64, 'big') + B.to_bytes(64, 'big'))
		u = digest.finalize()
		u = int.from_bytes(u, 'big') % N
		print("Server: u = {0}".format(u))
		sys.stdout.flush()
		
		# Compute the server key = (Av**u)**b (mod N)
		skey = pow(((A % N)*(pow(v, u, N))), b, N)
		print("Server: k_server = {0}".format(skey))
		sys.stdout.flush()
		
		# Calculate the hash to compare to M1
		M1s = A.to_bytes(64, 'big') + B.to_bytes(64, 'big') + skey.to_bytes(64, 'big')
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(M1s)
		M1s = digest.finalize()
		M1 = conn.recv(32)
		print("Server: M1 = <{0}>".format(M1.hex()))
		sys.stdout.flush()
		
		# Compare the calculated hash with the received hash
		if M1 == M1s:
			print("Server: 'Negotiation successful.'")
			sys.stdout.flush()
		else:
			exit()
			
		# Calculate M2 and then send it to the client
		M2 = A.to_bytes(64, 'big') + M1 + skey.to_bytes(64, 'big')
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(M2)
		M2 = digest.finalize()
		print("Server:	M2 = <{0}>".format(M2.hex()))
		sys.stdout.flush()
		
		print("Server:	Sending M2 <{0}>".format(M2.hex()))
		sys.stdout.flush()
		conn.send(M2)

		# Shut down the server
		conn.shutdown(socket.SHUT_RDWR)
		conn.close()
		
sys.exit(0)
