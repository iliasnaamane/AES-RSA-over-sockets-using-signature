from socket import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5 
import time

## Generate RSA private & public keys
random_generator = Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()

## Server Binding
HOST = "localhost" #localhost
PORT = 8794
s = socket(AF_INET, SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(6)
conn, addr = s.accept()
print "Server is running"

# Unpadding for AES decryption message
def pkcs5_unpad(s):
    s = s[0:-ord(s[-1])]
    return s

# decrypt data using RSA private key
def decryptRSA(data,private_key):
	print "decryptRSA....\n"
	data = data.replace("encryptedRSA=",'')
	print "RSA key encrypted:"+str(data)
	encrypted = eval(data)
	decrypted = private_key.decrypt(encrypted)
	return decrypted

# encrypt data using RSA private key
def encryptRSA(data,string):
	#Convert string to key
	server_public_key = RSA.importKey(server_string)
	encrypted = server_public_key.encrypt(string, 32)
	return encrypted

#decrypt message using AES
def decryptAES(aesKey, iv, ciphertext):
	cipher = AES.new(unhexlify(aesKey), AES.MODE_CBC, unhexlify(iv))
	return pkcs5_unpad(cipher.decrypt(unhexlify(ciphertext)))

# Hash using SHA256
def hashMessage(string):
	digest = SHA256.new()
	digest.update(string)
	return digest

def sign(message, priv_key):
	signer = PKCS1_v1_5.new(priv_key)
	digest = hashMessage(message)
	return signer.sign(digest)

while True:
	# First message from the client which normally indicates that connection is ok
	time.sleep(2)
	data = conn.recv(1024)
	data = data.replace("\r\n", '')
	if data == "connexion ok":
		conn.send("public key:"+public_key.exportKey()+"\n")
		time.sleep(2)
		conn.send("Hello I am the server")
		time.sleep(2)
		conn.send("Signature"+sign("Hello I am the server",private_key))
		time.sleep(2)
	# Decrypt aesKey using RSA private key
	elif "encryptedRSA" in data:
		aesKey= decryptRSA(data,private_key)
		conn.send("Server: OK")
		print "Decrypted aes key = " + aesKey
	# Receive initialization vector from the client
	elif "Init Vector" in data:
		iv = data.replace("Init Vector=",'')
		print "Init Vector="+iv+"\n"
	# Receive encrypted message and decrypt it using aes key ( Previously decrypt it by RSA)
	elif "encryptedMessage" in data:
		data = data.replace("encryptedMessage=","")
		print "Encrypted message = "+data+"\n"
		decrypted = decryptAES(aesKey,iv,data)
		print "Decrypted message="+ decrypted + "\n"
	elif data == "Quit": break

#Stop server
conn.send("Server stopped")
print "server stopped"
conn.close()