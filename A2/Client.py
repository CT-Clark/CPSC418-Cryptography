# Cody Clark
# 30010560
# Client.py
#!/usr/bin/env python3

# Client socket program
# sys.stdout.flush()
#import utilities
import socket
import sys, os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
#import sympy
HOST = '127.0.4.18'  # The server's hostname or IP address. This is the local host address
PORT = 31802        # The port used by the server, usually between 0 - 65535. Lower ports may be resrved

# Generate a random 16-byte salt, s
s = 0
while len(bin(s)[2:]) != (128):
	s = secrets.randbits(128)
	
print("Client: s = {0}".format(s))
sys.stdout.flush()

# Ask for username and password via standard input
print("Please enter a username: ")
uname = sys.stdin.readline()
sys.stdout.flush()
uname = uname.strip("\n")
print("Client: I = {0}".format(uname))
sys.stdout.flush()
# encode it as bytes, and record the length
unamebytes = uname.encode('utf-8')
# convert and store the length in a 4byte array in big-endian
unamelength = len(unamebytes).to_bytes(4, 'big')
print("Client: |I| = <{0}>".format(unamelength.hex()))
sys.stdout.flush()

print("Please enter a password: ")
pword = sys.stdin.readline()
sys.stdout.flush()
# encode it as bytes, and record the length
pwordbytes = pword.encode('utf-8')
#sys.stdout.flush()

#creates client string to be sent
clientdata = unamelength + unamebytes 

sp = s.to_bytes(16, 'big') + pwordbytes

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(sp)
x = digest.finalize()
print("Client: x = {0}".format(x.hex()))
sys.stdout.flush()


#----------#----------#----------#----------#


# Perform registration with the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
	#connect to server
	conn.connect((HOST, PORT))
    
	# Receive N and g from the server
	N = conn.recv(64)
	print("Client: N = {0}".format(int.from_bytes(N, 'big')))
	sys.stdout.flush()
	g = conn.recv(64)
	print("Client: g = {0}".format(int.from_bytes(g, 'big')))
	sys.stdout.flush()
	
	v = pow(int.from_bytes(g, 'big'), int.from_bytes(x, 'big'), int.from_bytes(N, 'big'))
	print("Client: v = {0}".format(v))
	sys.stdout.flush()
	
	# Client sends data to the server
	print("Client: Sending <{0}>".format('r'.encode('utf-8').hex()))
	sys.stdout.flush()
	print("Client: Sending |I| <{0}>".format(len(unamebytes).to_bytes(4, 'big').hex()))
	sys.stdout.flush()
	print("Client: Sending I {0}".format(uname))
	sys.stdout.flush()
	print("Client: Sending s <{0}>".format(s.to_bytes(16, 'big').hex()))
	sys.stdout.flush()
	print("Client: Sending v <{0}>".format(v.to_bytes(64, 'big').hex()))
	sys.stdout.flush()
	conn.sendall('r'.encode('utf-8') + clientdata + s.to_bytes(16, 'big') + v.to_bytes(64,'big'))
	
	x = 0 # Disposing of x as per step 4
	
	print("Client:	'Registration successful.'")
	sys.stdout.flush()
	
	conn.shutdown(socket.SHUT_RDWR)
	conn.close()
	
	
#----------#----------#----------#----------#
	

# This is the second time the client connects to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
	#connect to server
	conn.connect((HOST, PORT))
    
	# Receive N and g from the server
	N = int.from_bytes(conn.recv(64), 'big')
	print("Client: N = {0}".format(N))
	sys.stdout.flush()
	g = int.from_bytes(conn.recv(64), 'big')
	print("Client: g = {0}".format(g))
	sys.stdout.flush()
	
	a = secrets.randbelow(N-1) # 1 <= a <= N-2 < N-1
	print("Client:	a = {0}".format(a))
	sys.stdout.flush()

	A = pow(g, a, N)
	print("Client: A = {0}".format(A))
	sys.stdout.flush()
	
	# Client sends data to the server
	print("Client: Sending <{0}>".format('p'.encode('utf-8').hex()))
	sys.stdout.flush()
	print("Client: Sending |I| <{0}>".format(len(unamebytes).to_bytes(4, 'big').hex()))
	sys.stdout.flush()
	print("Client: Sending I {0}".format(uname))
	sys.stdout.flush()
	print("Client: Sending A <{0}>".format(A.to_bytes(64, 'big').hex()))
	sys.stdout.flush()
	conn.sendall('p'.encode('utf-8') + clientdata + A.to_bytes(64, 'big'))
	# Client receives data from server
	s2 = int.from_bytes(conn.recv(16), 'big')
	print("Client: s = {0}".format(s2))
	sys.stdout.flush()
	B = int.from_bytes(conn.recv(64), 'big')
	print("Client: B = {0}".format(B))
	sys.stdout.flush()
	
	# Compute u = H(A||B) (mod N)
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(A.to_bytes(64, 'big') + B.to_bytes(64, 'big'))
	u = digest.finalize()
	u = int.from_bytes(u, 'big') % N
	print("Client: u = {0}".format(u))
	sys.stdout.flush()
	
	# Compute client key = (B-kv)**(a+ux) (mod N)
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(sp)
	x = int.from_bytes(digest.finalize(), 'big')
	
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(N.to_bytes(64, 'big') + g.to_bytes(64, 'big'))
	k = int.from_bytes(digest.finalize(), 'big')
	
	ckey = pow(int((B-int(k*v))), int((a+int(u*x))), N)
	print("Client: k_client = {0}".format(ckey))
	sys.stdout.flush()
	
	# Compute M1
	M1 = A.to_bytes(64, 'big') + B.to_bytes(64, 'big') + ckey.to_bytes(64, 'big')
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(M1)
	M1 = digest.finalize()
	print("Client: Sending M1 {0}".format(M1.hex()))
	sys.stdout.flush()
	conn.send(M1)
	
	M2 = conn.recv(32)
	print("Client: M2 = {0}".format(M2.hex()))
	sys.stdout.flush()
	
	M2c = A.to_bytes(64, 'big') + M1 + ckey.to_bytes(64, 'big')
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(M2c)
	M2c = digest.finalize()
	
	# Compare the calculated hash with the received hash
	if M2 == M2c:
		print("Client: 'Negotiation successful.'")
		sys.stdout.flush()
	else:
		exit()
	
	conn.shutdown(socket.SHUT_RDWR)
	conn.close()
