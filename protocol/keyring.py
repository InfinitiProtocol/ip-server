from protocol import infiniti_pb2, ipfs_key_pb2
import secp256k1, base64, hashlib, os, ecdsa, hmac, random, struct, zlib
from secp256k1 import ALL_FLAGS
from hashlib import sha256
import hashlib,sha3
from utils import base58
from utils.crypto import hasher, PRNG
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import int_to_string, string_to_int
from ecdsa.numbertheory import square_root_mod_prime as sqrt_mod
from utils.coins import COINS
import protocol.infiniti_pb2  
from config import *
import base64
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA 
import six 
from binascii import hexlify
from utils import base58

CURVE_GEN       = ecdsa.ecdsa.generator_secp256k1
CURVE_ORDER     = CURVE_GEN.order()
FIELD_ORDER     = SECP256k1.curve.p()
INFINITY        = ecdsa.ellipticcurve.INFINITY
CONFIG  =   {
				'EntropyBits': 256
			} 
class IPFSKeyMessage():
	def __init__(self,data,pubkey=False):
		if pubkey:
			self.protobuf = ipfs_key_pb2.PublicKey()
		else:
			self.protobuf = ipfs_key_pb2.PrivateKey()
		self.protobuf.Type = ipfs_key_pb2.RSA
		self.protobuf.Data = data

	def Serialize(self):
		return self.protobuf.SerializeToString()

	def Save(self,fname):
		import os
		try:
			ipfs_keystore = os.environ['IPFS_PATH'] + '/keystore'
		except:
			from os.path import expanduser
			home = expanduser("~")
			ipfs_keystore = home + '/.ipfs/keystore'
		filename = ipfs_keystore + '/' + fname
		with open(filename,"w") as f:
			f.write(self.Serialize())
	

class Keyring():
	def Key(self, entropy=None, fingerprint=None, RSAlen = 2048):
		self.entropy = entropy
		self.rsa = None
		self.rsa_len = RSAlen
		I = hmac.new("Infiniti seed", entropy, hashlib.sha512).digest()
		Il, Ir = I[:32], I[32:]
		# FIXME test Il for 0 or less than SECP256k1 prime field order
		assert Il > 0

		self.k = ecdsa.SigningKey.from_string(entropy, curve=SECP256k1)
		self.K = self.k.get_verifying_key()
		self.C = Il

		self._fingerprint = fingerprint
		key = self
		if self._fingerprint is not None:
			self.fingerprint = self._fingerprint
			_keyspec = list(chunks(self._fingerprint,4))
			for x in range(0,len(_keyspec)):
				spec = '\0' * (4 - len(_keyspec[x])) + _keyspec[x]
				node = struct.unpack("<L",spec)[0]
				key = key.ChildKey(node)
		return key

	def Entropy(self):
		return self.entropy

	def Fingerprint(self):
		return self.fingerprint

	def GetHash(self):
		protobuf = infiniti_pb2.Fingerprint()
		protobuf.version = FINGERPRINT_VERSION
		protobuf.fingerprint = "".join(self.Fingerprint())
		return hashlib.sha3_256(protobuf.SerializeToString()).digest()

	def ChildKey(self, i):
		# Index as bytes, BE
		i_str = struct.pack(">L", i)

		# Data to HMAC
		data = b'\0' + self.k.to_string() + i_str
		# Get HMAC of data
		(Il, Ir) = self.hmac(data)

		# Construct new key material from Il and current private key
		Il_int = string_to_int(Il)
		if Il_int > CURVE_ORDER:
			return None
		pvt_int = string_to_int(self.k.to_string())
		k_int = (Il_int + pvt_int) % CURVE_ORDER
		if (k_int == 0):
			return None
		secret = (b'\0'*32 + int_to_string(k_int))[-32:]
		
		# Construct and return a new Key
		return self.Key(secret)

	# ElGamal for SECP256k1 ECDSA functions
	def ElGamalEncrypt(self, m,key = None, curved=SECP256k1.curve,generator=CURVE_GEN):
		if key is None:
			key = self.PublicKey()
		pubkey = key
		r=''
		msg = self.private_header(m,0)+m
		msg = msg+('\x00'*( 32-(len(msg)%32) ))
		msgs = chunks(msg,32)

		_r  = CURVE_ORDER

		P = generator
		if len(pubkey)==33: #compressed
			pk = ecdsa.ellipticcurve.Point( curved, string_to_int(pubkey[1:33]), self.ECC_YfromX(string_to_int(pubkey[1:33]), curved, pubkey[0]=='\x03')[0], _r )
		else:
			pk = ecdsa.ellipticcurve.Point( curved, string_to_int(pubkey[1:33]), string_to_int(pubkey[33:65]), _r )

		for g in msgs:
			rand=( ( '%013x' % long(random.random() * 0xfffffffffffff) )*5 )

			n = long(rand,16) >> 4
			Mx = string_to_int(g)
			My,xoffset=self.ECC_YfromX(Mx, curved)
			M = ecdsa.ellipticcurve.Point( curved, Mx+xoffset, My, _r )

			T = P*n
			U = pk*n + M

			toadd = self.ser(T) + self.ser(U)
			toadd = chr(ord(toadd[0])-2+2*xoffset)+toadd[1:]
			r+=toadd
		return zlib.compress(base64.b64encode(self.public_header(pubkey,0) + r))

	def ElGamalDecrypt(self,enc, curved=SECP256k1.curve, verbose=False, generator=CURVE_GEN):
		P = generator
		pvk=string_to_int(self.PrivateKey())
		pubkeys = [self.ser((P*pvk),True), self.ser((P*pvk),False)]
		enc = base64.b64decode(zlib.decompress(enc))

		assert enc[:2]=='\x6a\x6a'      

		phv = string_to_int(enc[2])
		assert phv==0, "Can't read version %d public header"%phv
		hs = string_to_int(enc[3:5])
		public_header=enc[5:5+hs]
		checksum_pubkey=public_header[:2]

		address=filter(lambda x:sha256(x).digest()[:2]==checksum_pubkey, pubkeys)
		assert len(address)>0, 'Bad private key'
		address=address[0]
		enc=enc[5+hs:]

		r = ''
		for Tser,User in map(lambda x:[x[:33],x[33:]], chunks(enc,66)):
			ots = ord(Tser[0])
			xoffset = ots>>1
			Tser = chr(2+(ots&1))+Tser[1:]
			T = self.pointSerToPoint(Tser,curved,generator)
			U = self.pointSerToPoint(User,curved,generator)

			V = T*pvk
			Mcalc = U+(self.negative_self(V))
			r += ('%064x'%(Mcalc.x()-xoffset)).decode('hex')

		pvhv = string_to_int(r[0])
		assert pvhv==0, "Can't read version %d private header"%pvhv
		phs = string_to_int(r[1:3])
		private_header = r[3:3+phs]
		size = string_to_int(private_header[:4])
		checksum = private_header[4:6]
		r = r[3+phs:]

		msg = r[:size]
		hashmsg = sha256(msg).digest()[:2]
		checksumok = hashmsg==checksum        

		return [msg, checksumok, address]

	# AES functions
	def AESEncrypt(self, raw):
		raw = self._pad(raw)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(self.PrivateKey(), AES.MODE_CBC, iv)
		return base64.b64encode(iv + cipher.encrypt(raw))

	def AESDecrypt(self, enc):
		enc = base64.b64decode(enc)
		iv = enc[:AES.block_size]
		cipher = AES.new(self.PrivateKey(), AES.MODE_CBC, iv)
		return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

	# RSA Functions
	def GenerateRSA(self):
		self.rsa = RSA.generate(self.rsa_len, randfunc=PRNG(self.Entropy()))

	def RSAPublic(self):
		if self.rsa is None:
			self.GenerateRSA()
		return self.rsa.publickey().exportKey("PEM") 

	def RSAPrivate(self):
		if self.rsa is None:
			self.GenerateRSA()
		return self.rsa.exportKey("PEM")

	def RSAEncrypt(self, msg, recipient_key=None):
		if recipient_key is None:
			recipient_key = RSA.importKey(self.RSAPublic())
		pko = PKCS1_OAEP.new(recipient_key)
		enc = pko.encrypt(msg)
		return base64.b64encode(enc)

	def RSADecrypt(self, enc):
		enc = base64.b64decode(enc)
		pko = PKCS1_OAEP.new(RSA.importKey(self.RSAPrivate()))
		dec = pko.decrypt(enc)
		return six.text_type(dec, encoding='utf8')

	# IPFS
	def ExportRSAtoIPFS(self):
		if self.rsa is None:
			self.GenerateRSA()
		key = self.rsa.exportKey("DER")
		ipfs_key = IPFSKeyMessage(key)
		ipfs_key.Save(hexlify(self.Fingerprint()))

	def PeerId(self,privkey):
		# TODO : Not quite working yet, DO NOT USE!
		from utils import multihash
		if self.rsa is None:
			self.GenerateRSA()
		if privkey:
			k = IPFSKeyMessage(self.rsa.exportKey("DER"))
		else:
			k = IPFSKeyMessage(self.rsa.publickey().exportKey("DER"))
		h = multihash.encode(base64.b64encode(k.Serialize()),multihash.SHA2_256)
		return base58.encode(str(h))

	# SECP3256k1 ECDSA Functions
	def PublicKey(self, compressed=True):
		if compressed:		
			if self.K.pubkey.point.y() & 1:
				ck = b'\3'+int_to_string(self.K.pubkey.point.x())
			else:
				ck = b'\2'+int_to_string(self.K.pubkey.point.x())
			return ck
		else:
			return self.K.to_string()

	def PrivateKey(self):
		return self.k.to_string()

	def Identifier(self, compressed=True):
		cK = self.PublicKey(compressed)
		return hashlib.new('ripemd160', sha256(cK).digest()).digest()

	def Address(self, prefix='Infiniti', cK=None):
		if prefix == "Ethereum":
			if cK is None:
				cK = self.PublicKey()
			return "0x" + hexlify(hashlib.sha3_256(cK).digest())[0:40]
		else:
			if cK is None:
				i = self.Identifier()
			else:
				i = hashlib.new('ripemd160', sha256(cK).digest()).digest()
			vh160 =COINS[prefix]['main']['prefix'].decode('hex')+i
			return base58.check_encode(vh160)

	def WIF(self, prefix):
		if prefix == "Ethereum":
			return "0x" + hexlify(self.PrivateKey())
		else:
			raw = COINS[prefix]['main']['secret'].decode('hex') + self.k.to_string() + '\x01' # Always compressed
			return base58.check_encode(raw)

	def Sign(self, msg, compressed=True, coin='Infiniti'):
		self.msgprefix=coin + ' Signed Message:\n'
		privkey = secp256k1.PrivateKey()
		privkey.set_raw_privkey(self.PrivateKey())
		msg = msg.encode('utf8')
		fullmsg = (varint(len(self.msgprefix)) + self.msgprefix + varint(len(msg)) + msg)
		hmsg = sha256(sha256(fullmsg).digest()).digest()

		rawsig = privkey.ecdsa_sign_recoverable(hmsg, raw=True)
		sigbytes, recid = privkey.ecdsa_recoverable_serialize(rawsig)

		meta = 27 + recid
		if compressed:
			meta += 4

		res = base64.b64encode(chr(meta).encode('utf8') + sigbytes)
		return res

	def RecoverPublicKey(self, message,signature):
		if len(signature) != 65:
			raise Exception("Invalid signature length")
		empty = secp256k1.PublicKey(flags=ALL_FLAGS)
		sig = p.ecdsa_recoverable_deserialize(sigbytes[1:], rec_id)

		pubkey = empty.schnorr_recover(message,signature)
		return secp256k1.PublicKey(pubkey)

	def Verify(self, base64sig, msg, address=None, coin='Infiniti', ctx=None):
		self.msgprefix=coin + ' Signed Message:\n'
		if address is None:
			address=self.Address(coin)
		if len(base64sig) != 88:
			raise Exception("Invalid base64 signature length")

		msg = msg.encode('utf8')
		fullmsg = (varint(len(self.msgprefix)) + self.msgprefix + varint(len(msg)) + msg)
		hmsg = sha256(sha256(fullmsg).digest()).digest()

		sigbytes = base64.b64decode(base64sig)
		if len(sigbytes) != 65:
			raise Exception("Invalid signature length")

		compressed = (ord(sigbytes[0:1]) - 27) & 4 != 0
		rec_id = (ord(sigbytes[0:1]) - 27) & 3

		p = secp256k1.PublicKey(ctx=ctx, flags=ALL_FLAGS)
		sig = p.ecdsa_recoverable_deserialize(sigbytes[1:], rec_id)

		# Recover the ECDSA public key.
		recpub = p.ecdsa_recover(hmsg, sig, raw=True)
		pubser = secp256k1.PublicKey(recpub, ctx=ctx).serialize(compressed=compressed)

		vh160=COINS[coin]['main']['prefix'].decode('hex')+hashlib.new('ripemd160', sha256(pubser).digest()).digest()
		addr = base58.check_encode(vh160)
		return addr == address

	def _pad(self, s):
		return s + (32 - len(s) % 32) * chr(32 - len(s) % 32)

	@staticmethod
	def _unpad(s):
		return s[:-ord(s[len(s)-1:])]

	def hmac(self, data):
		I = hmac.new(self.C, data, hashlib.sha512).digest()
		return (I[:32], I[32:])

	def pointSerToPoint(self,Aser, curved=SECP256k1.curve, generator=CURVE_GEN):
		_r  = generator.order()
		assert Aser[0] in ['\x02','\x03','\x04']
		if Aser[0] == '\x04':
			return ecdsa.ellipticcurve.Point( curved, string_to_int(Aser[1:33]), string_to_int(Aser[33:]), _r )
		Mx = string_to_int(Aser[1:])
		return ecdsa.ellipticcurve.Point( curved, Mx, self.ECC_YfromX(Mx, curved, Aser[0]=='\x03')[0], _r )

	def ECC_YfromX(self,x,curved=SECP256k1.curve, odd=True):
		_p = curved.p()
		_a = curved.a()
		_b = curved.b()
		for offset in range(128):
			Mx=x+offset
			My2 = pow(Mx, 3, _p) + _a * pow(Mx, 2, _p) + _b % _p
			My = pow(My2, (_p+1)/4, _p )

			if curved.contains_point(Mx,My):
				if odd == bool(My&1):
					return [My,offset]
				return [_p-My,offset]
		raise Exception('ECC_YfromX: No Y found')

	def private_header(self,msg,v):
		assert v<1, "Can't write version %d private header"%v
		r=''
		if v==0:
			r+=('%08x'%len(msg)).decode('hex')
			r+=sha256(msg).digest()[:2]
		return ('%02x'%v).decode('hex') + ('%04x'%len(r)).decode('hex') + r

	def public_header(self,pubkey,v):
		assert v<1, "Can't write version %d public header"%v
		r=''
		if v==0:
			r=sha256(pubkey).digest()[:2]
		return '\x6a\x6a' + ('%02x'%v).decode('hex') + ('%04x'%len(r)).decode('hex') + r

	def negative_self(self, point):
		return ecdsa.ellipticcurve.Point( point.curve(), point.x(), -point.y(), point.order() )

	def ser( self, point, comp=True ):
		x = point.x()
		y = point.y()
		if comp:
			return ( ('%02x'%(2+(y&1)))+('%064x'%x) ).decode('hex')
		return ( '04'+('%064x'%x)+('%064x'%y) ).decode('hex')

def chunks(l, n):
	"""Yield successive n-sized chunks from l."""
	for i in xrange(0, len(l), n):
		yield l[i:i+n]

def varint(size):
	# Variable length integer encoding:
	# https://en.bitcoin.it/wiki/Protocol_documentation
	if size < 0xFD:
		return struct.pack(b'<B', size)
	elif size <= 0xFFFF:
		return b'\xFD' + struct.pack(b'<H', size)
	elif size <= 0xFFFFFFFF:
		return b'\xFE' + struct.pack(b'<I', size)
	else:
		return b'\xFF' + struct.pack(b'<Q', size)

