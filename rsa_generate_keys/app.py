import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import secrets

def generate_keys():
	random_generator = Random.new().read
	key = RSA.generate(1024, random_generator)
	private, public = key, key.publickey()
	private = private.exportKey().decode('utf-8')
	public = public.exportKey().decode('utf-8')
	with open("pubkey.pem","w") as file: file.write(public)
	with open("privkey.pem","w") as file: file.write(private)

generate_keys()
print("Done!")

