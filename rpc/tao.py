from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from config import chains, isValidAppId, APP_ID
import json, base64
from database import client
from binascii import hexlify,unhexlify
from utils.base58 import burn_address

def BlockchainDaemon(app):
	try:
		uri = "http://%s:%s@%s:%s"%(chains[chains['active']]["user"], chains[chains['active']]["password"], chains[chains['active']]["server"], chains[chains['active']]["port"])
		client.UpdateChainStatus('XTO','OK')
		a = True
		return AuthServiceProxy(uri)
	except:
		a = False
	if not a:
		app.logger.error("Cannot connect to %s daemon.", chains[chains['active']]["abbr"])
		client.UpdateChainStatus('XTO','OFFLINE')

def ProcessBlock(app,block):
	app.logger.info("Processing block #%s: %s", block["height"], block["hash"])
	td = BlockchainDaemon(app)
	for tx in block['tx']:
		rawtx = td.getrawtransaction(tx)
		transaction = td.decoderawtransaction(rawtx)
		for vout in transaction["vout"]:
			if "OP_RETURN" in vout["scriptPubKey"]["asm"]:
				tag = vout["scriptPubKey"]["asm"].replace("OP_RETURN","").strip()
				if tag == hexlify(hexlify(APP_ID[0]))[0:40] or tag == hexlify(hexlify(APP_ID[1])[0:40]):
					app.logger.info('Data found @ %s in block %s', tx, block['height'])
					# It's OP_RETURN, but is there a valid JSON data block with it?
					txdata = base64.b64decode(transaction["data"])
					# We're pulling down all IP data, we don't care what app it's for yet 
					# Just store it in the SQL table 
					if not client.SaveTXData(chains[chains['active']]["abbr"],tx,txdata,block['height']):
						app.logger.warning("Data found in TX %s but malformed, skipping.", tx)

def ScanMempool(app):
	td = BlockchainDaemon(app)
	txdata = td.getrawmempool()
	for tx in txdata:
		rawtx = td.getrawtransaction(tx)
		transaction = td.decoderawtransaction(rawtx)
		for vout in transaction["vout"]:
			if "OP_RETURN" in vout["scriptPubKey"]["asm"]:
				tag = vout["scriptPubKey"]["asm"].replace("OP_RETURN","").strip()
				if tag == hexlify(hexlify(APP_ID[0]))[0:40] or tag == hexlify(hexlify(APP_ID[1])[0:40]):
					# It's OP_RETURN, but is there a valid JSON data block with it?
					txdata = base64.b64decode(transaction["data"])
					# We're pulling down all IP data, we don't care what app it's for yet 
					# Just store it in the SQL table 
					if not client.SaveTXData(chains[chains['active']]["abbr"],tx,txdata,None):
						app.logger.warning("Data found in TX %s but malformed, skipping.", tx)

def SyncChain(app,rescan=True):
	# The process of validating a blockchain by the hash values is VITAL to the trust relationships possible
	# through the mathematics.  This process is similar to the operation of Electrum and other Simple Payment
	# Verification schemas.  Since we are not validating payments, this is Simple Data Verification (or SDV).

	# Start at the genesis block
	td = BlockchainDaemon(app)
	lb = hexlify(client.GetLastBlockProcessed())
	if rescan:
		data=td.getblock(chains[chains['active']]["genesis"])
		client.TruncateBlockDataTable()
	else:
		data=td.getblock(lb)
	client.UpdateChainStatus('XTO','SYNC')
	while data.has_key('nextblockhash'):
		try:
			prev_hash=data['hash']
			data=td.getblock(data['nextblockhash'])
			if prev_hash !=  data['previousblockhash']:          
				app.logger.info("Hash match sanity check failed: %s", data['hash'])
			ProcessBlock(app,data)
		except Exception as inst:
			app.logger.error(type(inst))    # the exception instance
			app.logger.error(inst.args)     # arguments stored in .args
			app.logger.error(inst)
			break
		if not client.UpdateLastBlockHash(chains[chains['active']]["abbr"],data['hash']):
			app.logger.error("Error updating last block hash.")			

def CheckBalance(app):
	td = BlockchainDaemon(app)
	derp=td.getinfo()
	return derp['balance']

def commit_object(app,msg):
	address = burn_address()
	try:
		#data =	BlockchainDaemon(app).sendtoaddress(address,0.0001,base64.b64encode(msg),hexlify(APP_ID[1])[0:40]) # Always APP_ID 1
		return True
	except JSONRPCException, e:
		app.logger.error(type(e))    # the exception instance
		app.logger.error(e.args)     # arguments stored in .args
		app.logger.error(e)
		return False
