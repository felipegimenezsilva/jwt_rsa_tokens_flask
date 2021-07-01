from certs import get_key_file
import jwt

keys = {}

class Errors:
	
	def __init__(self):
		self._errors = { 'errors' : []}
	
	def error(self):
		return len(self._errors['errors']) > 0
	
	def new_error(self,message):
		self._errors['errors'].append({
			'error' : message
		})
		
	def get_errors(self):
		return self._errors

class JWT_inspect(Errors):

	def __init__(self,service_name):
		super().__init__()
		self.service = service_name
		self.key = self._get_pk()

	# search a public key file to validate a jwt
	def _get_pk(self):
		pubk = keys.get(self.service,None)
		if not pubk :
			file = get_key_file(self.service)
			if not file : 
				self.new_error("service certificate not found")
				return None
			try:
				with open(file,"rb") as pkfile:
					pubk = jwt.jwk_from_pem(pkfile.read())
				return pubk
			except:	
				self.new_error("certificate file incorrect")
				return None
	
	# apply a list of validations in a jws
	def check(self,compact_jws):
		if not self.key :
			self.new_error("can't validate the request")
			return self._errors
		jwt_instance = jwt.JWT()
		try:
			message_received = jwt_instance.decode(compact_jws,self.key,do_time_check=True)
		except:
			self.new_error("not authorized")
			return self._errors
		if message_received.get('iss',None) != self.service :
			self.new_error('incompatible service name')
			return self._errors
		return message_received
		
	
