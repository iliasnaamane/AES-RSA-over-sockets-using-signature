from socket import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import DES

random_generator = Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()

HOST = "localhost" #localhost
PORT = 7777
s = socket(AF_INET, SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(4)
conn, addr = s.accept()
print "Server is running"

def decryptRSA(data,private_key):
	print "decryptRSA....\n"
	
	data = data.replace("encryptedRSA=",'')
	print "RSA key encrypted:"+str(data)
	encrypted = eval(data)
	decrypted = private_key.decrypt(encrypted)
	return decrypted

def decryptDES(desKey,data):
	print "decryptDES.....\n"
	data = data.replace("encryptedMessage=",'')
	des =  DES.new(desKey)
	return des.decrypt(data)



while True:
	data = conn.recv(1024)
	data = data.replace("\r\n", '')
	if data == "connexion ok":
		conn.send("public key:"+public_key.exportKey()+"\n")

	elif "encryptedRSA" in data:
		desKey= decryptRSA(data,private_key)
		conn.send("Server: OK")
		print "Decrypted des key = " + desKey
	elif "encryptedMessage" in data:
		print "Encrypted Message : "+data
		decrypted = decryptDES(desKey,data)
		print "Decrypted message = "+ decrypted
	elif data == "Quit": break

#Stop server
conn.send("Server stopped")
print "server stopped"
conn.close()