from socket import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
## Generate RSA private & public keys
random_generator = Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()

## Server Binding
HOST = "localhost" #localhost
PORT = 8787
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
	print "ciphertext="+unhexlify("ef531f5d790bcf1d72e1ab109076f177")
	return pkcs5_unpad(cipher.decrypt(unhexlify(ciphertext)))

while True:
	# First message from the client which normally indicates that connection is ok
	data = conn.recv(1024)
	data = data.replace("\r\n", '')
	if data == "connexion ok":
		conn.send("public key:"+public_key.exportKey()+"\n")
	# Decrypt aesKey using RSA private key
	elif "encryptedRSA" in data:
		aesKey= decryptRSA(data,private_key)
		conn.send("Server: OK")
		print "Decrypted aes key = " + aesKey
	# Receive initialization vector from the client
	elif "Init Vector" in data:
		iv = data.replace("Init Vector=",'')
		print "Init Vector="+iv
	# Receive encrypted message and decrypt it using aes key ( Previously decrypt it by RSA)
	elif "encryptedMessage" in data:
		data = data.replace("encryptedMessage=","")
		decrypted = decryptAES(aesKey,iv,data)
		print "Decrypted message="+ decrypted
	elif data == "Quit": break

#Stop server
conn.send("Server stopped")
print "server stopped"
conn.close()