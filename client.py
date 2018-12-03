import socket
from binascii import hexlify, unhexlify
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, AES
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5 
# Establish connection to the server
s = socket.socket()
s.connect(("localhost",8788))
print("connection ok")
s.sendall("connexion ok")

# Block size for AES
BS=16
aesKey = '2b7e151628aed2a6abf7158809cf4f3c'

# http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256

# Padding to be multiple of BS
def pkcs5_pad(s):
    BLOCK_SIZE = 16
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
# RSA encryption
def encryptRSA(server_public_key,string):
	encrypted = server_public_key.encrypt(string, 32)
	return encrypted

# generate Initialization vector for AES
def generateInitVector():
	return Random.new().read(AES.block_size)

# AES encryption
def encryptAES(aesKey, iv, msg):
	msg = pkcs5_pad(msg)
	cipher = AES.new(unhexlify(aesKey), AES.MODE_CBC, unhexlify(iv))
	return hexlify(cipher.encrypt(msg))

from Crypto.Signature import PKCS1_v1_5 # Hash using SHA256
# Hash using SHA256
def hashMessage(string):
	digest = SHA256.new()
	digest.update(string)
	return digest

def verify(message, signature, public_key):
	signer = PKCS1_v1_5.new(public_key) 
	digest = hashMessage(message)
	return signer.verify(digest, signature)

while True:
	server_string = s.recv(1024)
	server_string = server_string.replace("\r\n", '')
	if "public key" in server_string:
		# Clean public key string
		server_string = server_string.replace("public key:", '')
		server_string = server_string.replace("\r\n", '')
		print server_string
		#Convert string to key
		server_public_key = RSA.importKey(server_string)
		# encrypt aes key using RSA public key received from the server
		encryptedRSA = encryptRSA(server_public_key,aesKey)
		print "encryptedRSA="+str(encryptedRSA)+"\n"
		# send aesKey encrypted with RSA public key to the server
		s.sendall("encryptedRSA="+str(encryptedRSA))
	elif "Hello I am" in server_string:
		serverMessage = server_string
		print "Server Message: "+serverMessage+"\n"
	elif "Signature" in server_string:
		signature = server_string.replace("Signature","")
		print "Signature: "+hexlify(signature)+"\n"
		assert verify(serverMessage, signature, server_public_key)
		print "Verification OK"
		# open input to the user
		message = raw_input()
		# generate initialization vector in hexadecimal format and send it to the server
		iv = hexlify(generateInitVector())
		print "Init Vector="+iv
		s.sendall("Init Vector="+iv)
		# encrypt the message using AES and send it to the server
		encryptedAES = encryptAES(aesKey,iv,message)
		print "Encrypted Message="+encryptedAES
		s.sendall("encryptedMessage="+str(encryptedAES))
		#Server's response if Server OK the server decrypt the message
		server_response = s.recv(1024)
		server_response = server_response.replace("\r\n", '')
		if server_response == "Server: OK":
		    print "Le serveur a decrypte le message"
		#Tell server to finish connection
		#s.sendall("Quit")
		print(s.recv(1024)) #Quit server response
		s.close()
