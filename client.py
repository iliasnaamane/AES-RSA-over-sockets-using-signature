import socket
from binascii import hexlify, unhexlify
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, AES
from Crypto import Random

# Establish connection to the server
s = socket.socket()
s.connect(("localhost",8787))
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
def encryptRSA(server_string,string):
	server_string = server_string.replace("public key:", '')
	server_string = server_string.replace("\r\n", '')
	#Convert string to key
	server_public_key = RSA.importKey(server_string)
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

#Receive public key string from server
serverString = s.recv(1024)
# encrypt aes key using RSA public key received from the server
encryptedRSA = encryptRSA(serverString,aesKey)
print "encryptedRSA="+str(encryptedRSA)
# send aesKey encrypted with RSA public key to the server
s.sendall("encryptedRSA="+str(encryptedRSA))
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
