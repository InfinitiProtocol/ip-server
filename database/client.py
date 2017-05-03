import sqlite3
import config, os
from config import DATABASES
from flask import g
from binascii import unhexlify, hexlify
import psycopg2 as psql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT # <-- ADD THIS LINE

def UpdateChainStatus(chain,status):
	db = OpenDB()
	dbcur = db.cursor()
	dbcur.execute("UPDATE chain_state SET status = %s WHERE chain=%s;",(status, chain,))
	db.commit()
	db.close()

def GetChainStatus(chain):
	db = OpenDB()
	dbcur = db.cursor()
	dbcur.execute("SELECT status FROM chain_state WHERE chain=%s;",(chain,))
	row = dbcur.fetchone()
	db.commit()
	db.close()
	return row[0]

def checkTableExists(db,tablename):
	dbcur = db.cursor()
	dbcur.execute("SELECT 1 AS result FROM pg_tables WHERE schemaname='public' and tablename=%s;",(tablename,))
	row = dbcur.fetchone()
	return row is not None

def GetLastBlockProcessed(chain='XTO'):
	db = OpenDB()
	dbcur = db.cursor()
	dbcur.execute("""
		SELECT last_block_hash 
		FROM chain_state
		WHERE chain = %s
		""",(chain,))
	try:
		ans = str(dbcur.fetchone()[0])
	except:
		for chain in config.chains:
			dbcur.execute("INSERT INTO chain_state (chain,last_block_hash) VALUES (%s,%s);", (config.chains[chain]['abbr'],psql.Binary(unhexlify(config.chains[chain]['genesis']))))
		db.commit()
		dbcur.execute("""
			SELECT last_block_hash 
			FROM chain_state
			WHERE chain = %s
			""",(chain,))
		ans = str(dbcur.fetchone()[0])
	db.close()
	return ans

def GetNewsAuthor(object_id):
	return LoadNewsItem(object_id)[0]

def LoadNewsItem(object_id):
	db = OpenDB()
	dbcur = db.cursor()
	sql = "select C.issuer, C.issued, A.title, A.content, A.version, A.debug from news AS A INNER JOIN objects AS B ON B.id = A.object INNER JOIN messages AS C ON C.hash = B.message WHERE A.object = %s"
	dbcur.execute(sql,(object_id,))
	row = dbcur.fetchone()
	db.close()
	if row is not None:
		return row
	else:
		return None 

def GetPassphraseByAddress(addr):
	db = OpenDB()
	dbcur = db.cursor()
	sql = "SELECT FindIdentityByAddress(%s);"
	dbcur.execute(sql,(addr,))
	row = dbcur.fetchone()
	db.close()
	if row is not None:
		return row[0]
	else:
		return None 

def GetPassphraseByFingerprint(fp):
	db = OpenDB()
	dbcur = db.cursor()
	sql = "SELECT id_string FROM identities WHERE fingerprint = %s;"
	dbcur.execute(sql,(psql.Binary(unhexlify(fp)),))
	row = dbcur.fetchone()
	db.close()
	if row is not None:
		return row[0]
	else:
		return None 

def GetKeysByFingerprint(fp):
	db = OpenDB()
	dbcur = db.cursor()
	sql = "SELECT A.* FROM pubkeys AS A INNER JOIN (SELECT pubkey FROM identities WHERE fingerprint = %s) AS B ON A.owner_pubkey = B.pubkey;"
	dbcur.execute(sql,(psql.Binary(fp),))
	rows = dbcur.fetchall()
	db.close()
	if rows is not None:
		return rows
	else:
		return None 

def GetIdentities(local,max_per_page=10,offset=1):
	db = OpenDB()
	dbcur = db.cursor()
	if int(local) == 0:
		local_str = ""
	else:
		local_str = "A.local IS TRUE AND "
	sql = "SELECT A.name,fingerprint,infinitiaddress FROM (SELECT A.name,ENCODE(A.pubkey,'hex') as pubkey,A.bitcoinaddress,A.taoaddress,A.infinitiaddress,A.ethereumaddress,A.rsa_pubkey,ENCODE(B.fingerprint,'hex') as fingerprint,B.id_string IS NOT NULL AS local, A.primary FROM pubkeys AS A INNER JOIN (SELECT pubkey, id_string,fingerprint FROM identities) AS B ON A.owner_pubkey = B.pubkey) AS A WHERE " + local_str + "A.primary = 0 LIMIT " + str(max_per_page) + " OFFSET " + str(offset) + ";"
	dbcur.execute(sql)
	rows = dbcur.fetchall()
	db.close()
	if rows is not None:
		return rows
	else:
		return None 

def GetPubkeyForAddress(addr):
	db = OpenDB()
	dbcur = db.cursor()
	sql = "SELECT pubkey FROM pubkeys WHERE BitcoinAddress = %s OR TaoAddress = %s OR InfinitiAddress = %s OR EthereumAddress = %s;"
	dbcur.execute(sql,(addr,addr,addr,addr,))
	row = dbcur.fetchone()
	if row is not None:
		return row[0]
	else:
		return None 

def GetFingerprintForAddress(addr):
	# These messages came in from the blockchain but haven't been processed yet
	db = OpenDB()
	dbcur = db.cursor()
	sql = """
	SELECT fingerprint, A.location FROM 
		(SELECT fingerprint, pubkey, 0 AS location
			FROM identities
			UNION
			SELECT fingerprint, pubkey, 1 AS location
			FROM fingerprints) AS A
		INNER JOIN
		pubkeys AS B ON A.pubkey = B.pubkey
		WHERE B.BitcoinAddress=%s OR B.TaoAddress=%s OR B.InfinitiAddress=%s OR B.EthereumAddress=%s
	"""
	dbcur.execute(sql,(addr,addr,addr,addr,))
	row = dbcur.fetchone()
	if row is not None:
		return row
	else:
		return None 

def GetUnprocessedMessages():
	# These messages came in from the blockchain but haven't been processed yet
	db = OpenDB()
	dbcur = db.cursor()
	sql = "SELECT cd_txhash, cd_message, hash, txhash FROM (SELECT A.txhash AS cd_txhash,A.message AS cd_message,B.* FROM chain_data AS A LEFT OUTER JOIN messages AS B ON A.txhash = B.txhash) AS A WHERE txhash IS NULL;"
	dbcur.execute(sql)
	rows = dbcur.fetchall()
	db.close()
	return rows

def GetMempoolMessages():
	# Mempool messages are in chain_data database but aren't in a block yet (block_height is NULL)
	db = OpenDB()
	dbcur = db.cursor()
	sql = "SELECT message FROM chain_data WHERE block_height IS NULL;"
	dbcur.execute(sql)
	ids = GetIdentities(1,1000000)
	rows = dbcur.fetchall()
	db.close()
	return rows

def ImportIdentity(i):
	db = OpenDB()
	dbcur = db.cursor()
	dbcur.execute("UPDATE identities SET id_string = %s WHERE fingerprint = %s AND id_string IS NULL;", (i.Passphrase(),psql.Binary(i.Fingerprint()),))
	db.commit()
	db.close()
	return True

def TruncateBlockDataTable():
	# These messages came in from the blockchain but haven't been processed yet
	db = OpenDB()
	dbcur = db.cursor()
	sql = "TRUNCATE TABLE chain_data"
	dbcur.execute(sql)
	db.close()
	UpdateLastBlockHash(config.chains[config.chains['active']]['abbr'],config.chains[config.chains['active']]['genesis'])

def LoadIdentity(fp):
	db = OpenDB()
	dbcur = db.cursor()
	dbcur.execute("""
		SELECT fingerprint, A.version, pubkey, rsa_pubkey, B.name AS name, C.issued AS packed_timestamp,
		CASE WHEN id_string IS NULL
			THEN 0
			ELSE 1
		END AS local
		FROM identities AS A 
		INNER JOIN objects AS B ON A.object=B.id 
		INNER JOIN messages AS C ON B.message=C.hash
		WHERE A.fingerprint = %s;
		""", (psql.Binary(fp),))
	row = dbcur.fetchone()
	db.commit()
	db.close()
	return row

def LoadIdentityByPubkey(pk):
	db = OpenDB()
	dbcur = db.cursor()
	dbcur.execute("""
		SELECT fingerprint, A.version, pubkey, rsa_pubkey, B.name AS name, C.issued AS packed_timestamp,
		CASE WHEN id_string IS NULL
			THEN 0
			ELSE 1
		END AS local
		FROM identities AS A 
		INNER JOIN objects AS B ON A.object=B.id 
		INNER JOIN messages AS C ON B.message=C.hash
		WHERE A.pubkey = %s;
		""", (psql.Binary(pk),))
	row = dbcur.fetchone()
	db.commit()
	db.close()
	return row

def SaveTXData(chain,_hash,txdata,block_height=None):
	db = OpenDB()
	dbcur = db.cursor()
	# If the block_height is None it came from the mempool.
	if block_height is not None:
		# From the blockchain...
		# Do I already have a copy of this without the block height (from the mempool)?
		sqlite_str = """
			SELECT 1 AS result FROM chain_data WHERE txhash=%s and block_height IS NULL
			"""
		dbcur.execute(sqlite_str,(psql.Binary(unhexlify(_hash)),))
		row = dbcur.fetchone()
		if row is not None:
			# Yes, so just fill in the height
			sqlite_str = """
					UPDATE chain_data SET block_height=%s WHERE txhash=%s;
				"""
			dbcur.execute(sqlite_str,(block_height,psql.Binary(unhexlify(_hash)),))
		else:
			# Do I have a copy of this with the block height?
			sqlite_str = """
				SELECT 1 AS result FROM chain_data WHERE txhash=%s and block_height=%s
				"""
			dbcur.execute(sqlite_str,(psql.Binary(unhexlify(_hash)),block_height,))
			row = dbcur.fetchone()
			if row is None:
				# It's brand new, so insert it in all it's glory
				sqlite_str = """
						INSERT INTO chain_data (chain,txhash,message,block_height) VALUES (%s,%s,%s,%s);
					"""
				dbcur.execute(sqlite_str,(chain,psql.Binary(unhexlify(_hash)),psql.Binary(txdata),block_height,))
	else:
		# From the mempool...
		# Do I already have it?
		sql = "SELECT 1 AS result FROM chain_data WHERE txhash = %s;"
		dbcur.execute(sql,(psql.Binary(unhexlify(_hash)),))
		row = dbcur.fetchone()
		if row is None:
			# No, insert it
			sqlite_str = """
				INSERT INTO chain_data (chain,txhash,message) VALUES (%s,%s,%s);
			"""
			dbcur.execute(sqlite_str,(chain,psql.Binary(unhexlify(_hash)),psql.Binary(txdata),))
	db.commit()
	db.close()
	return True

def SaveMessage(msg,dbcur):
	# Check the message
	sql = "SELECT 1 AS result FROM messages WHERE hash = %s;"
	dbcur.execute(sql,(psql.Binary(msg.GetHash()),))
	row = dbcur.fetchone()
	if row is None:
		# Insert the message
		sqlite_string = """
			INSERT INTO messages (txhash, hash, version, application_id, message_type, metadata, issuer, issued, signature)
				VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
		"""			
		dbcur.execute(sqlite_string,(psql.Binary(msg.TXHash()),psql.Binary(msg.GetHash()),msg.Version(),psql.Binary(msg.ApplicationId()),msg.MessageType(),psql.Binary(msg.Metadata()),psql.Binary(msg.Issuer()),psql.Binary(msg.Issued()),msg.Signature(),
			))
	else:
		# Do we just need to update the TX hash?
		sqlite_string = """
			UPDATE messages SET txhash = %s WHERE hash = %s;
		"""			
		dbcur.execute(sqlite_string,(psql.Binary(msg.TXHash()),psql.Binary(msg.GetHash()),
			))

def SaveObject(obj,msg,dbcur):
	# Check the object
	sql = "SELECT 1 AS result FROM objects WHERE id = %s;"
	dbcur.execute(sql,(psql.Binary(obj.GetHash()),))
	row = dbcur.fetchone()
	if row is None:
		sqlite_string = """
			INSERT INTO objects (version, name, id, metadata, issue_mode, object_type, encryption, encryption_key, message)
				VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
		"""
		dbcur.execute(sqlite_string,(obj.Version(),obj.Name(),psql.Binary(obj.Id()),psql.Binary(obj.Metadata()),obj.IssueMode(),obj.ObjectType(),obj.Encryption(),psql.Binary(obj.EncryptionKey()),psql.Binary(msg.GetHash()),
			))

def SaveIdentityMessage(msg,obj,im,i):
	db = OpenDB()
	dbcur = db.cursor()
	SaveMessage(msg,dbcur)
	SaveObject(obj,msg,dbcur)
	# Check the id
	sql = "SELECT 1 AS result FROM identities WHERE fingerprint = %s;"
	dbcur.execute(sql,(psql.Binary(im.Fingerprint()),))
	row = dbcur.fetchone()
	if row is None:
		sqlite_string = """
			INSERT INTO identities (fingerprint, version, id_string, object, pubkey,rsa_pubkey)
				VALUES (%s, %s, %s, %s, %s, %s);
		"""
		if i is not None:
			# This is an id created locally or imported
			id_string = i.Passphrase()
		else:
			# This is an id from the blockchain
			id_string = None
		dbcur.execute(sqlite_string,(psql.Binary(im.Fingerprint()),im.Version(),id_string,psql.Binary(obj.Id()),psql.Binary(im.PublicKey()),im.RSAPublicKey(),
			))
	db.commit()
	db.close()
	return True

def SaveFingerprintMessage(msg,obj,fp):
	db = OpenDB()
	dbcur = db.cursor()
	SaveMessage(msg,dbcur)
	SaveObject(obj,msg,dbcur)
	sql = "SELECT 1 AS result FROM fingerprints WHERE fingerprint = %s;"
	dbcur.execute(sql,(psql.Binary(fp.Fingerprint()),))
	row = dbcur.fetchone()
	if row is None:
		pubkey = fp.PublicKey()
		sqlite_string = """
			INSERT INTO fingerprints (version, fingerprint, pubkey, id_fingerprint, object, rsa_pubkey)
				SELECT %s as version, %s as fingerprint, %s as pubkey, identities.fingerprint as id_fingerprint, %s as object, %s as rsa_pubkey 
					FROM identities WHERE pubkey = %s
		"""
		dbcur.execute(sqlite_string,(fp.Version(),psql.Binary(fp.Fingerprint()),psql.Binary(pubkey),psql.Binary(obj.Id()),fp.RSAPublicKey(),psql.Binary(msg.Issuer()),
			))
	db.commit()
	db.close()
	return True

def SaveFileMessage(msg,obj,f):
	db = OpenDB()
	dbcur = db.cursor()
	SaveMessage(msg,dbcur)
	SaveObject(obj,msg,dbcur)
	sql = "SELECT 1 AS result FROM files WHERE address = %s;"
	dbcur.execute(sql,(f.Address(),))
	row = dbcur.fetchone()
	if row is None:
		pubkey = fp.PublicKey()
		sqlite_string = """
			INSERT INTO files
				(version,address,name,file_type,comment,object) VALUES
				(%s,%s,%s,%s,%s,%s)
		"""
		dbcur.execute(sqlite_string,(f.Version(),f.Address(),f.Name(),f.FileType(),f.Comment(),psql.Binary(obj.Id()),
			))
	db.commit()
	db.close()
	return True

def UpdateLastBlockHash(chain,block_hash):
	try:
		db = OpenDB()
		psql_str = """
			UPDATE chain_state SET last_block_hash=%s WHERE chain=%s;
		"""
		db.cursor().execute(psql_str,(psql.Binary(unhexlify(block_hash)),chain,))
		db.commit()
		db.close()
		return True
	except:
		return False

def MessageExistsOnDisk(h):
	db = OpenDB()
	dbcur = db.cursor()
	dbcur.execute("""
		SELECT 1 AS result
		FROM messages 
		WHERE hash=?
		""",[h])
	row = dbcur.fetchone()
	db.close()
	return row is not None

def InitDB(app=None):
	db = OpenDB()
	if not checkTableExists(db,'chain_state'):
		#	CREATE USER {0} PASSWORD %s;
		#	ALTER USER {1} WITH SUPERUSER; 
		psql_setup = """
			CREATE TABLE IF NOT EXISTS public.chain_state
			(
			    chain text COLLATE pg_catalog."default" NOT NULL,
			    last_block_hash bytea NOT NULL,
			    status text NULL,
			    CONSTRAINT chain_state_pkey PRIMARY KEY (last_block_hash)
			)
			WITH (
			    OIDS = FALSE
			)
			TABLESPACE pg_default;
			ALTER TABLE public.chain_state
			    OWNER to infiniti;

			CREATE TABLE IF NOT EXISTS public.chain_data
			(
			    chain text NOT NULL,
			    txhash bytea NOT NULL,
			    message bytea NOT NULL,
			    block_height integer,
			    PRIMARY KEY (txhash)
			)
			WITH (
			    OIDS = FALSE
			);
			ALTER TABLE public.chain_data
			    OWNER to infiniti;

				CREATE TABLE IF NOT EXISTS public.messages
			(
				txhash bytea NULL,
				hash bytea NOT NULL,
			    version integer NOT NULL,
			    application_id bytea NOT NULL,
			    message_type integer NOT NULL,
			    metadata bytea NOT NULL,
			    issuer bytea NOT NULL,
			    issued bytea NOT NULL,
			    signature text NOT NULL,
			    PRIMARY KEY (hash)
			)
			WITH (
			    OIDS = FALSE
			);
			ALTER TABLE public.messages
			    OWNER to infiniti;

				CREATE TABLE IF NOT EXISTS public.objects
			(
			    version integer NOT NULL,
			    name text NULL,
			    id bytea NOT NULL,
			    metadata bytea NOT NULL,
			    issue_mode integer NOT NULL,
			    object_type integer NOT NULL,
			    encryption integer NOT NULL,
			    encryption_key bytea NOT NULL,
			    message bytea NOT NULL REFERENCES messages(hash),
			    PRIMARY KEY (id)
			)
			WITH (
			    OIDS = FALSE
			);
			ALTER TABLE public.objects
			    OWNER to infiniti;

			CREATE TABLE IF NOT EXISTS public.identities (
				fingerprint bytea NOT NULL,
				version integer NOT NULL,
				id_string text NULL,
				pubkey bytea NOT NULL,
				rsa_pubkey text NULL,
				object bytea NOT NULL REFERENCES objects(id),
				PRIMARY KEY(fingerprint)
			)
			WITH (
			    OIDS = FALSE
			);
			ALTER TABLE public.identities
			    OWNER to infiniti;

			CREATE TABLE IF NOT EXISTS public.fingerprints (
				version integer NOT NULL,
				fingerprint bytea NOT NULL,
				pubkey bytea NOT NULL,
				id_fingerprint bytea REFERENCES identities(fingerprint),
				rsa_pubkey text NULL,
				object bytea REFERENCES objects(id),
				PRIMARY KEY(fingerprint)
			)
			WITH (
			    OIDS = FALSE
			);
			ALTER TABLE public.fingerprints
			    OWNER to infiniti;

			CREATE TABLE IF NOT EXISTS public.files (
				version integer NOT NULL,
				address text NOT NULL,
				name text NOT NULL,
				file_type text NOT NULL,
				comment text NOT NULL,
				object bytea REFERENCES objects(id),
				PRIMARY KEY(address)
			)
			WITH (
			    OIDS = FALSE
			);
			ALTER TABLE public.files
			    OWNER to infiniti;

			CREATE TABLE IF NOT EXISTS public.news (
				version integer NOT NULL,
				title text NOT NULL,
				content text NOT NULL,
				debug boolean NOT NULL,
				image text NOT NULL,
				object bytea REFERENCES objects(id),
				PRIMARY KEY(title)
			)
			WITH (
			    OIDS = FALSE
			);
			ALTER TABLE public.files
			    OWNER to infiniti;
    	"""
   		db.cursor().execute(psql_setup)
    	#""".format(DATABASES['postgresql']['user'],DATABASES['postgresql']['user'],)
   		#db.cursor().execute(psql_setup,(DATABASES['postgresql']['password'],))
		db.commit()
   		psql_setup2 = """
			CREATE LANGUAGE plpython2u;  

			CREATE OR REPLACE FUNCTION public.bitcoinaddress(pubkey bytea)
			    RETURNS character varying
			    LANGUAGE 'plpython2u'
			    COST 100.0
			    VOLATILE NOT LEAKPROOF 
			AS $BODY$

					from pycoin.key import Key
					from pycoin.serialize import h2b
					import binascii
					key_sec_c = Key.from_sec(h2b(binascii.hexlify(pubkey)))
					return key_sec_c.address()

			$BODY$;
			ALTER FUNCTION public.bitcoinaddress(pubkey bytea)
			    OWNER TO infiniti;

			CREATE OR REPLACE FUNCTION public.taoaddress(pubkey bytea)
			    RETURNS character varying
			    LANGUAGE 'plpython2u'
			    COST 100.0
			    VOLATILE NOT LEAKPROOF 
			AS $BODY$

				from pycoin.encoding import hash160, hash160_sec_to_bitcoin_address
				from pycoin.serialize import h2b
				import binascii
                
				return hash160_sec_to_bitcoin_address(hash160(h2b(binascii.hexlify(pubkey))), address_prefix=b'\x42')

			$BODY$;
			ALTER FUNCTION public.taoaddress(pubkey bytea)
			    OWNER TO infiniti;

			CREATE OR REPLACE FUNCTION public.ethereumaddress(pubkey bytea)
			    RETURNS character varying
			    LANGUAGE 'plpython2u'
			    COST 100.0
			    VOLATILE NOT LEAKPROOF 
			AS $BODY$

				import binascii,hashlib,sha3

				return "0x" + binascii.hexlify(hashlib.sha3_256(pubkey).digest())[0:40]

			$BODY$;
			ALTER FUNCTION public.ethereumaddress(pubkey bytea)
			    OWNER TO infiniti;

			CREATE OR REPLACE FUNCTION public.infinitiaddress(
				pubkey bytea)
			    RETURNS character varying
			    LANGUAGE 'plpython2u'
			    COST 100.0
			    VOLATILE 
			AS $function$
							from pycoin.encoding import hash160, hash160_sec_to_bitcoin_address
							from pycoin.serialize import h2b
							import binascii
			                
							return hash160_sec_to_bitcoin_address(hash160(h2b(binascii.hexlify(pubkey))), address_prefix=b'\x67')						
			$function$;
			ALTER FUNCTION public.infinitiaddress(bytea)
			    OWNER TO infiniti;

			CREATE OR REPLACE VIEW public.pubkeys AS
			 SELECT e.pubkey,
			    bitcoinaddress(e.pubkey) AS bitcoinaddress,
			    taoaddress(e.pubkey) AS taoaddress,
			    infinitiaddress(e.pubkey) AS infinitiaddress,
			    ethereumaddress(e.pubkey) AS ethereumaddress,
			    e.rsa_pubkey,
			    e.owner_pubkey,
			    '-1'::integer AS "primary",
			    e.name
			   FROM ( SELECT a.pubkey,
			            a.rsa_pubkey,
			            d.pubkey AS owner_pubkey,
			            b.name
			           FROM fingerprints a
			             JOIN objects b ON b.id = a.object
			             JOIN messages c ON c.hash = b.message
			             JOIN identities d ON d.pubkey = c.issuer) e
			UNION
			 SELECT f.pubkey,
			    bitcoinaddress(f.pubkey) AS bitcoinaddress,
			    taoaddress(f.pubkey) AS taoaddress,
			    infinitiaddress(f.pubkey) AS infinitiaddress,
			    ethereumaddress(f.pubkey) AS ethereumaddress,
			   f.rsa_pubkey,
			    f.owner_pubkey,
			    0 AS "primary",
			    f.name
			   FROM ( SELECT d.pubkey,
			            d.rsa_pubkey,
			            d.pubkey AS owner_pubkey,
			            b.name
			           FROM identities a
			             JOIN objects b ON b.id = a.object
			             JOIN messages c ON c.hash = b.message
			             JOIN identities d ON d.pubkey = c.issuer) f;

			ALTER TABLE public.pubkeys
			    OWNER TO infiniti;


			CREATE OR REPLACE FUNCTION public.FindIdentityByAddress(
				address char)
			    RETURNS char
			    LANGUAGE 'sql'
			    COST 100.0
			    VOLATILE 
			AS $function$
			SELECT A.id_string 
				FROM identities AS A
			    INNER JOIN public.pubkeys AS B ON A.pubkey = B.pubkey
			    WHERE B.bitcoinaddress = address
			    OR B.taoaddress = address
			    AND id_string IS NOT NULL;
			$function$;
			ALTER FUNCTION public.FindIdentityByAddress(char)
			    OWNER TO infiniti;

			CREATE UNIQUE INDEX fingerprints_pubkey
				ON public.fingerprints USING btree
				(pubkey)
				TABLESPACE pg_default;
			CREATE UNIQUE INDEX identities_pubkey
				ON public.identities USING btree
				(pubkey)
				TABLESPACE pg_default;
			CREATE INDEX objects_enckey
				ON public.objects USING btree
				(encryption_key ASC NULLS LAST)
				TABLESPACE pg_default;
			CREATE INDEX messages_issuer
				ON public.messages USING btree
				(issuer)
				TABLESPACE pg_default;
   		"""
   		db.cursor().execute(psql_setup2)
		db.commit()
		#for chain in config.chains:
		active = config.chains['active']
		abbr = config.chains[active]['abbr']
		genesis = config.chains[active]['genesis']
		db.cursor().execute("INSERT INTO chain_state (chain,last_block_hash) VALUES (%s,%s);", (abbr,psql.Binary(unhexlify(genesis))))
		db.commit()
		db.close()
		return True
	else: 
		db.close()
		return False

def OpenDB():
	con = psql.connect(dbname='postgres',
		user=DATABASES['postgresql']['user'], host=DATABASES['postgresql']['server'],
		password=DATABASES['postgresql']['password'])

	con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT) # <-- ADD THIS LINE
	cur = con.cursor()
	cur.execute('SELECT 1 AS result FROM pg_database WHERE datname=%s;',[DATABASES['postgresql']['db'],])
	row = cur.fetchone()
	if row is None:
		cur.execute("CREATE DATABASE %s ;" % DATABASES['postgresql']['db'])
	return psql.connect(dbname=DATABASES['postgresql']['db'],
		user=DATABASES['postgresql']['user'], host=DATABASES['postgresql']['server'],
		password=DATABASES['postgresql']['password'])		
