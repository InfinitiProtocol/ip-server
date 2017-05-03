from flask import Flask, request, Response, jsonify, abort,render_template
from functools import wraps
from config import infiniti
from utils.sentencegenerator import generateSentences
from protocol import identity
from protocol.messages import *
from binascii import unhexlify, hexlify
from utils.crypto import unpackTime
from database.client import GetPassphraseByAddress,GetFingerprintForAddress,GetKeysByFingerprint,GetPassphraseByFingerprint,TruncateBlockDataTable
from database.client import GetIdentities, GetChainStatus, GetMempoolMessages
import requests, json

app = Flask(__name__,static_url_path='/static', template_folder='templates')

def check_auth(username, password):
	return username == infiniti['user'] and password == infiniti['password']

def authenticate():
	return Response(
	'Could not verify access for that URL.\n'
	'One must login with proper credentials', 401,
	{'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		auth = request.authorization
		if not auth or not check_auth(auth.username, auth.password):
			return authenticate()
		return f(*args, **kwargs)
	return decorated

def getkeysbyfingerprint(j,t):
	pp = GetKeysByFingerprint(j)
	if pp is None:
		return jsonify(results={
				'success': False,
				'message': 'Fingerprint matches no local identity.'
			})
	else:
		l = []
		import json
		for data in pp:
			i = {
				'pubkey' : hexlify(data[0]),
				'bitcoin' : data[1],
				'tao' : data[2],
				'infiniti' : data[3],
				'ethereum' : data[4],
				'rsa' : data[5],
				'root' : True if data[7] > -1 else False,
			}
			l.append(i)
		if t:
			return l
		else:
			return json.dumps({ 'fingerprint': j['fingerprint'].encode('utf-8'), 'keys' : l })

def getidentity(fp):
	im = IdentityMessage().Load(fp)
	if im is None: 
		return jsonify(results={
				'success': False,
			})
	else:
		k = getkeysbyfingerprint(im.Fingerprint(),True)
		return jsonify(identity=im.toJSON(),keys=k)

# User Interfaces
# Dashboard
@app.route('/', methods=['GET'])
def index():
	return render_template('dashboard.html')

# Identity
@app.route('/id/<id>', methods=['GET'])
def id():
	id_browse()
@app.route('/id/browse', methods=['GET'])
def id_browse():
	return render_template('id_browse.html', breadcrumb = 'Identitiy | Browse', breadcrumb_url = '/id/browse', rpc_user = infiniti['user'], rpc_password = infiniti['password'])
@app.route('/id/import', methods=['GET'])
def id_import():
	return render_template('id.html', breadcrumb = 'Identitiy | Import', breadcrumb_url = '/id/import')
@app.route('/id/migrate', methods=['GET'])
def id_migrate():
	return render_template('id.html', breadcrumb = 'Identitiy | Migrate', breadcrumb_url = '/id/migrate')

# Decentralize Exchange
@app.route('/dex', methods=['GET'])
def dex():
	return render_template('dex.html')

# Documents
@app.route('/doc/<id>', methods=['GET'])
def doc():
	id_browse()
@app.route('/doc/browse', methods=['GET'])
def doc_browse():
	return render_template('doc.html')
@app.route('/doc/register', methods=['GET'])
def doc_create():
	return render_template('doc.html')

# Ledgers
@app.route('/ledger/<id>', methods=['GET'])
def ledger():
	id_browse()
@app.route('/ledger/balances', methods=['GET'])
def ledger_browse():
	return render_template('ledger.html')
@app.route('/ledger/create', methods=['GET'])
def ledger_create():
	return render_template('ledger.html')

# Custom Objects
@app.route('/obj/<id>', methods=['GET'])
def obj():
	obj_browse()
@app.route('/obj/browse', methods=['GET'])
def obj_browse():
	return render_template('obj.html')
@app.route('/obj/create', methods=['GET'])
def obj_create():
	return render_template('obj.html')

# UI AJAX URLs
@app.route('/ui/id/browse/<local>', methods=['GET', 'POST'])
def ajax_get_identities(local):
	if type(int(local)) is not int:
		return jsonify(results={
				'success': False,
				'message': 'Local must be integer.'
			})
	start = request.args.get('start')
	length = request.args.get('length')
	search = request.args.get('search[value]')
	data = GetIdentities(local,length,start)
	if len(search) > 0:
		data = m = [row for row in data if search.upper() in row[0].upper() or search.upper() in row[1].upper() or search.upper() in row[2].upper()] 
	filtered = len(data) 
	results = {
		"draw": request.args.get('draw'),
		"recordsTotal": len(data),
		"recordsFiltered": filtered,
		'data' : data,
	}
	return jsonify(results)

@app.route('/ui/get_node_status/<node>', methods=['GET', 'POST'])
def ajax_get_node_stats(node):
	if node=='ipfs':
		pass
	else:
		status = GetChainStatus(node)
		return jsonify(status=status)

@app.route('/ui/get_mempool', methods=['GET', 'POST'])
def ajax_get_mempool():
	mp = GetMempoolMessages()
	response = []
	for m in mp:
		msg = Message().Deserialize(m)
		response.append(msg.toJSON())
	return jsonify(response)

@app.route('/ui/get_balance/<chain>', methods=['GET', 'POST'])
def ajax_get_balance(chain):
	total_balance = float(0)
	if chain == 'XTOn':
		from rpc import tao
		t = tao.BlockchainDaemon(app)
		total_balance = float(t.getbalance())
	else:
		ids = GetIdentities(1)
		for i in ids:
			keys = GetKeysByFingerprint(unhexlify(i[1]))
			if chain == 'BTC':
				for k in keys:
					url = 'http://btc.blockr.io/api/v1/address/info/' + k[1]
					response = requests.get(url)
					total_balance += float(response.json()['data']['balance'])
			if chain =='XTO':
				for k in keys:
					url = 'https://www.blockexperts.com/api?coin=tao&action=getbalance&address=' + k[2]
					response = requests.get(url)
					total_balance += float(response.json())
	return jsonify(balance=total_balance)
	#else:
	#	url = 'https://www.blockexperts.com/api?coin=tao&action=getbalance&address=' + address
	#	response = requests.post(url)
	#	return response

# APIs
# Create identity
@app.route('/api/create_identity', methods=['GET', 'POST'])
@requires_auth
def create_identity():
	passphrase = generateSentences()
	i = identity.Identity(passphrase)
	im = IdentityMessage(i)
	assert im.isValid()
	import json as j
	json = request.get_json()
	if not json or not 'name' in json:
		name = 'Anonymous'
	else:
		name = json['name']
	obj = ObjectMessage().Build(name, im.Serialize(), OBJECT_TYPE['identity'], ISSUE_MODE['none'])
	assert obj.isValid()
	msg = Message().Build(MESSAGES['create'], obj.Serialize(), i.Key(), APP_ID[0]) #ID is always 0
	assert msg.isValid()
	if msg.Commit(app):
		im.Save(msg,obj,i)
		i.Import()
		iden = getidentity(i.Fingerprint()).get_data()
		output = {
				'identity': iden,
				'passphrase': passphrase,
		}
		return jsonify(output)

# Import identity
@app.route('/api/import_identity', methods=['POST'])
@requires_auth
def import_identity():
	json = request.get_json()
	if not json or not 'passphrase' in json:
		abort(400)
	i = identity.Identity(json['passphrase'].encode('utf-8'))
	return jsonify(results={
			'success':i.Import(),
		})

# Get identity
@app.route('/api/get_identity', methods=['POST'])
@requires_auth
def get_identity():
	json = request.get_json()
	if json and 'fingerprint' in json:
		return getidentity(unhexlify(json['fingerprint'].encode('utf-8')))
	else:
		abort(400)

# Get identity
@app.route('/api/get_wif', methods=['POST'])
@requires_auth
def get_wif():
	json = request.get_json()
	if not json or not 'address' in json:
		abort(400)
	pp = GetPassphraseByAddress(json['address'].encode('utf-8'))
	if pp is None:
		return jsonify(results={
				'success': False,
				'message': 'Address matches no local identity.'
			})
	data = GetFingerprintForAddress(json['address'].encode('utf-8'))
	if data is None: 
		return jsonify(results={
				'success': False,
				'message': 'Address matches no address.'
			})
	else:
		if data[1] == 0:
			key = identity.Identity(pp).Key()
		else:
			key = identity.Identity(pp).Key(data[0])
		return jsonify(wif={
			'source':			'identity' if data[1]==0 else 'fingerprint', 
			'pubkey':			hexlify(key.PublicKey()), 
			'bitcoin_address':	key.Address('Bitcoin'),
			'bitcoin_wif':		key.WIF('Bitcoin'),
			'tao_address':		key.Address('Tao'),
			'tao_wif':			key.WIF('Tao'),
			'eth_address':		key.Address('Ethereum'),
			'eth_privkey':			key.WIF('Ethereum'),
		})

# Create keyspec 
@app.route('/api/create_fingerprint', methods=['POST'])
@requires_auth
def create_fingerprint():
	json = request.get_json()
	if not json or not 'fingerprint' in json:
		abort(400)
	pp = GetPassphraseByFingerprint(json['fingerprint'].encode('utf-8'))
	if pp is not None:
		i = identity.Identity(pp)
		k = i.Key(CreateKeyFingerprint())
		fp = FingerprintMessage(k)
		assert fp.isValid()
		obj = ObjectMessage().Build('Fingerprint', fp.Serialize(), OBJECT_TYPE['fingerprint'], ISSUE_MODE['none'])
		assert obj.isValid()
		msg = Message().Build(MESSAGES['create'], obj.Serialize(), i.Key(), APP_ID[0]) #Fingerprint is always 0
		assert msg.isValid()
		fp.Save(msg,obj)
		msg.Commit(app)
		return jsonify(fingerprint={
				'version':fp.Version(),
				'fingerprint':hexlify(fp.Fingerprint()),
				'owner':hexlify(i.Fingerprint()),
				'keys':	{
					'pubkey' : hexlify(k.PublicKey()),
					'bitcoin' : k.Address('Bitcoin'),
					'tao' : k.Address('Tao'),
					'infiniti' : k.Address('Infiniti'),
					'ethereum' : k.Address('Ethereum'),
					'rsa' : k.RSAPublicKey(),
				}
			})
	else:
		return jsonify(results={
				'success': False,
				'message': 'Fingerprint matches no local identity.'
			})

# Resync the blockchain
@app.route('/api/resync', methods=['POST', 'GET'])
@requires_auth
def resync():
	TruncateBlockDataTable()
	return jsonify(results={
			'success': True,
		})

