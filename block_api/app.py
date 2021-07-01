from flask import Flask, request

import jwt
from jwt_inspect import JWT_inspect

app = Flask(__name__)

# sample of usage
# this endpoint only permits tokens from 'service_01'
# send token by GET URL isn't the best way, but this is
# just to simplify some tests
@app.route("/service_01/<tok>",methods=['GET'])
def service_01(tok):
	inspect = JWT_inspect("service_01")
	json_msg = inspect.check(tok)
	if not inspect.error() : return json_msg
	else: return json_msg, 404
	
# sample of usage
# this endpoint only permits tokens from 'service_02'
@app.route("/service_02/<tok>",methods=['GET'])
def service_02(tok):

	# requesting the public key of 'service_02'
	# the 'service_02' certificate file is declared in certs.py
	inspect = JWT_inspect("service_02")
	
	# validation the token (origin, keys, etc)
	json_msg = inspect.check(tok)
	
	# if something wrong
	if inspect.error() : 
		
		# simple description of errors
		return inspect.get_errors(), 404
	
	# here, its all right to trust in the JSON origin
	return json_msg
	
app.run(port = 5000)	
