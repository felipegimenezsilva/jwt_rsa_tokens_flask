import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# converte bytes --> hexadecimal --> string
def _to_hex(msg):
	msg = (list(map(lambda x: hex(x).split('x')[-1],list(msg))))
	return "".join(list(map(lambda x: x if len(x) == 2 else f'0{x}', msg)))

# converte String -> hexadecimais --> bytes
def _from_hex(msg):
	return bytes([ int(f'0x{msg[i]}{msg[i+1]}',base=16) for i in range(0,len(msg),2)])

# recebe o nome do arquivo que contém o certificado
def _load_key(file):
	with open(file,"rb") as key: value = key.read()
	return RSA.importKey(value)

# realiza a descriptografia utilizando a chave privada
def _decrypt(ciphertext, priv_key):
	cipher = PKCS1_OAEP.new(priv_key)
	return cipher.decrypt(_from_hex(ciphertext))

# Não suporta criptografia de textos grandes ( > 70 chars).
# realiza a criptografia com uma chave publica
# OBS: mesmo sendo uma chave publica, para esse caso
# NÃO é ideal compartilha-la. Todos os serviços que
# possuirem acesso a chave, conseguirá criar mensagens
# validas. Porem, as chaves utilizadas aqui é para uso
# EXCLUSIVO deste serviço.
def _encrypt(message, pub_key):
	cipher = PKCS1_OAEP.new(pub_key)
	cipher = cipher.encrypt(message.encode('utf-8'))
	return _to_hex(cipher)

# aqui deverá receber o IDENTIFICADOR REAL do paciente
# e retorna um pseudonymo de 256 caracteres
# não aceita IDs grandes, utilizar Try Except
def get_pseudonyme(user_id):
	salt="MySalt@#$123"
	return  _encrypt(f'{user_id}_{salt}',_load_key("pubkey.pem"))
	
# recebe pseudonymo, e retorna o dado real
# chamar utilizando Try Except, já que a descriptografia dará
# errado ao enviar um valor não correspondente com o certificado
def get_real_identity(pseudonyme):
	real = _decrypt(pseudonyme,_load_key("privkey.pem")).decode('utf-8').split("_")
	real.pop(-1)
	return "".join(real)

#exemplo de uso
if __name__ == '__main__':
	my_pseudonyme_256= get_pseudonyme('6097f888fd11a33560fb9cae')
	my_mongo_real_id = get_real_identity(my_pseudonyme_256)
	print("real:",my_mongo_real_id)
	print("pseudonyme 256:",my_pseudonyme_256)



