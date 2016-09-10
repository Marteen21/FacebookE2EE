from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import fbchat
import pprint
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("-u", "--username", help="Username of the facebook account", type=str)
parser.add_argument("-p", "--password", help="Password of the facebook account", type=str)
parser.add_argument("-k", "--key", help="Encryption password", type=str)
parser.add_argument("-s", "--salt", help="Encryption salt", type=str)
parser.add_argument("-t", "--target", help="The facebook account name of the target", type=str)
args=parser.parse_args()
pp = pprint.PrettyPrinter(indent=4)




print("Trying to login with the given credentials")
success = 0
while (not success):
	try:
		client = fbchat.Client(loginusername, loginpassword)
		friends = client.getUsers(target)
		success = 1;
	except:
		print("Access denied.. retry")

friend = friends[0]
print(friend.uid)
password = b"kajakra"
salt = b"14"
kdf = PBKDF2HMAC(
	algorithm=hashes.SHA256(),
	length=32,
	salt=salt,
	iterations=100000,
	backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))
cipher_suite = Fernet(key)
sendingmode = 1
while(sendingmode):
	print("Sending mode, type quit to exit")
	messegetosend = raw_input("Please enter your message: ")
	if(messegetosend == "quit"):
		sendingmode=0
	else:
		#Encoding
		print("Key to decode: ", key)
		cipher_text = cipher_suite.encrypt(messegetosend)
		plain_text = cipher_suite.decrypt(cipher_text)
		print(cipher_text)
		sent = client.send(friend.uid, cipher_text)
		if sent:
		    print("Message sent successfully!")

last_messages = client.getThreadInfo(friend.uid,0)
last_messages.reverse()  # messages come in reversed order
print("last messages")
for message in last_messages:
	text2decrypt = message.body;
	b = bytes(text2decrypt)
	print(message.author_email + ":")
	try:
		print("Decoded: " + cipher_suite.decrypt(b))
	except:
		print("Can't decode " + b)
