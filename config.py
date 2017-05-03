DATABASES = {
	'msyql': {
		"server" : "",
		"port" : "",
		"db" : "",
		"user" : "",
		"password" : ""
	},

	'sqlite': { 
		"db" : "./ip.db"
	},

	'postgresql': {
		"server":"localhost",
		"port":5432,
		"db":"infiniti",
		"user":"infiniti",
		"password":"protocol"
	}
}

chains = {
	'active' : 'tao',
	'tao': {
		"abbr":'XTO',
		"server" : "localhost",
		"port" : "15151",
		"user" : "afl24FJCLkclaskdvn",
		"password" : "asdkncsalLCNLJECKAECnsklcjalsdkcjxLNJKDSCNLZKdj",
		"genesis" : "8e061f16ddf45f9cb3466461e56db35bea97e42a9e94e22151028a76ddb82ece",
		'gui-process' : 'Tao-Qt',
		'daemon-process' : 'taod',
	}

}

infiniti = {
				"user" : "rpcuser",
				"password" : "password",
				"encryption_password": "change me!",
			}

####
# Don't change anything below this line!
####
import hashlib, sha3

APP_ID = (
			hashlib.sha3_256("Identity").digest()					,	# Must always be present
			hashlib.sha3_256("Infiniti Protocol-dev-0.0.1").digest(), 
		)

CURRENT_VERSION 	= 	10001
ID_VERSION 			=	CURRENT_VERSION
MESSAGE_VERSION 	= 	CURRENT_VERSION
FINGERPRINT_VERSION = 	CURRENT_VERSION
OBJECT_VERSION 		= 	CURRENT_VERSION
LEDGER_VERSION 		= 	CURRENT_VERSION
TRANSFER_VERSION 	= 	CURRENT_VERSION
FILE_VERSION 		= 	CURRENT_VERSION
NEWS_VERSION 		= 	CURRENT_VERSION

def isValidAppId(app_id):
	from binascii import hexlify
	found = False
	for a in APP_ID:
		if app_id.encode('utf-8') == hexlify(a)[0:40].encode('utf-8'):
			found = True
	return found