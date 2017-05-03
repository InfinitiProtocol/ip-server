from keyring import Keyring
from protocol import infiniti_pb2  
from config import *
from utils.crypto import hasher
import hashlib,sha3,random,struct
from database.client import ImportIdentity

class Identity():
	def __init__(self, passphrase):
		self.passphrase = passphrase
		self._entropy = hasher(passphrase)
		tmp = hasher(passphrase, True)
		self._fingerprint = tmp[0:4] + tmp[-4:]

	def Passphrase(self):
		return self.passphrase

	def Version(self):
		return ID_VERSION

	def Entropy(self):
		return self._entropy
	
	def Fingerprint(self):
		return self._fingerprint

	def Key(self, fingerprint=None):
		if fingerprint is not None:
			return Keyring().Key(self.Entropy(),fingerprint)
		else: 
			return Keyring().Key(self.Entropy(),'')

	def GetHash(self):
		protobuf = infiniti_pb2.Identity()
		protobuf.version = ID_VERSION
		protobuf.fingerprint = self.Fingerprint()
		return hashlib.sha3_256(protobuf.SerializeToString()).digest()

	def RootAddress(self, coin=None):
		if coin == None:
			return self.Key().Address()
		elif coin == 'Bitcoin':
			return self.Key().Address('Bitcoin')
		elif coin == 'Tao':
			return self.Key().Address('Tao')

	def Import(self):
		return ImportIdentity(self)

def CreateKeyFingerprint():
	random.seed()
	final = []
	for x in range(0,6):
		leaf = random.SystemRandom().randint(int(0x000000),int(0xFFFFFF))
		final.append(struct.pack("<L",leaf))
	return buffer(''.join(final))

def Test():
	from binascii import hexlify
	# Create an identity, create a key, and run them through their paces
	passphrase = "Test passphrase."
	msg = "This is my test message."
	i = Identity(passphrase)
	rk = i.Key()
	# Create a new random key and do everything
	keyfp = CreateKeyFingerprint()
	key = i.Key(keyfp)
	signed = key.Sign(msg)
	verified = key.Verify(signed,msg,key.Address('Infiniti'))
	assert verified == True
	enc = key.ElGamalEncrypt(msg)
	dec = key.ElGamalDecrypt(enc)
	assert dec[1] == True
	enc = key.AESEncrypt(msg)
	dec = key.AESDecrypt(enc)
	assert dec.strip() == msg.strip()
	enc = key.RSAEncrypt(msg)
	print key.RSAPublic()
	dec = key.RSADecrypt(enc)
	assert dec.strip() == msg.strip()
	key.ExportRSAtoIPFS()
	print "Protocol identity tests passed."