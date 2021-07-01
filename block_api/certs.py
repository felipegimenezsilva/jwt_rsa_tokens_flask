# this names must be the same those sent through the field 'ISS', inside the JWT.
# the public keys must be the same public key generated by each service.

_public_keys = {
	"service_01" : 'public_keys/service_01.pem',
	"service_02" : 'public_keys/service_02.pem',
}

def get_key_file(service_name):
	return _public_keys.get(service_name,None)