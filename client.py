import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES

s = socket.socket()
s.connect(("localhost",7777))
s.sendall("connexion ok")


def encryptRSA(server_string,string):
	server_string = server_string.replace("public key:", '')
	server_string = server_string.replace("\r\n", '')
	#Convert string to key
	server_public_key = RSA.importKey(server_string)
	encrypted = server_public_key.encrypt(string, 32)
	return encrypted


def encryptDES(desKey, msg):
	des =  DES.new(desKey)
	if len(msg) % 8 != 0:
	    toAdd = 8 - len(msg) % 8
	print toAdd
	for i in range(0,toAdd):
		msg = msg+" "
	print msg
	cipher_text = des.encrypt(msg)
	return cipher_text




#Receive public key string from server
server_string = s.recv(1024)
#Encrypt message and send to server

desKey = '01234567'
encryptedRSA = encryptRSA(server_string,desKey)
print "Encrypted RSA: "+str(encryptedRSA)
s.sendall("encryptedRSA="+str(encryptedRSA))
message = raw_input()
encryptedDES = encryptDES(desKey,message)
print "Encrypted Message: "+encryptedDES
s.sendall("encryptedMessage="+encryptedDES)

#Server's response
server_response = s.recv(1024)
server_response = server_response.replace("\r\n", '')
if server_response == "Server: OK":
    print "Le serveur a decrypte le message"

#Tell server to finish connection
s.sendall("Quit")
print(s.recv(1024)) #Quit server response
s.close()