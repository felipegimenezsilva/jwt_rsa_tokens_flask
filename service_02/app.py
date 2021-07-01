from flask import Flask
import jwt
from jwt.utils import get_int_from_datetime
from datetime import datetime, timedelta, timezone

# CONFIGURATIONS --------------------------------------
service_num = 2
port = 5002

with open('privkey.pem','rb') as file:
	signing_key = jwt.jwk_from_pem(file.read())


app = Flask(__name__)


# route sample ----------------------------------------
'''
basic route to return a data using JWT
'''
@app.route("/")
def sample():
	jwt_instance = jwt.JWT()
	message = { 
		"data" : f'service {service_num} data sample',
		"iss" : f'service_0{service_num}',
		"iat" : get_int_from_datetime(datetime.now(timezone.utc)),
		'exp': get_int_from_datetime(datetime.now(timezone.utc)+timedelta(hours=1)),
	}
	compact_jws = jwt_instance.encode(message, signing_key, alg='RS512')
	return compact_jws

# running flask ----------------------------------------
app.run( port = port )
