from protocol import infiniti_pb2
import hashlib, base64, sha3
from binascii import hexlify, unhexlify
import copy, time, struct
from config import *
from utils.crypto import packTime, unpackTime
from protocol.identity import Keyring, CreateKeyFingerprint
from database.client import SaveIdentityMessage, SaveFingerprintMessage, GetUnprocessedMessages, LoadIdentity, GetNewsAuthor,LoadIdentityByPubkey
from rpc.tao import commit_object
import json
try:
	import cPickle as pickle
except:
	import pickle 

MESSAGES = { 
	'create':	infiniti_pb2.Message.CREATE,
	'update':	infiniti_pb2.Message.UPDATE,
	'transfer':	infiniti_pb2.Message.TRANSFER,
}
ISSUE_MODE = {
	'none':		infiniti_pb2.Object.NONE,
    'once':		infiniti_pb2.Object.ONCE,
    'multi':	infiniti_pb2.Object.MULTI,
    'singleton':infiniti_pb2.Object.SINGLETON,

}
OBJECT_TYPE = {
	'identity':		infiniti_pb2.Object.IDENTITY,
	'fingerprint':	infiniti_pb2.Object.FINGERPRINT,
	'ledger':		infiniti_pb2.Object.LEDGER,
	'file':			infiniti_pb2.Object.FILE,
	'custom':		infiniti_pb2.Object.CUSTOM,
}
ENCRYPTION = {
	'none':		infiniti_pb2.Object.UNENC,
	'aes':		infiniti_pb2.Object.AES,
	'rsa':		infiniti_pb2.Object.RSA,
	'elgamal':	infiniti_pb2.Object.ELGAMAL,
}
FENCRYPTION = {
	'none':		infiniti_pb2.File.UNENC,
	'aes':		infiniti_pb2.File.AES,
	'rsa':		infiniti_pb2.File.RSA,
	'elgamal':	infiniti_pb2.File.ELGAMAL,
}

def ProcessWaitingMessages(app):
	rows = GetUnprocessedMessages()
	for row in rows:
		if row[0] is not None:
			msg = Message(row[0]).Deserialize(row[1])
			obj = msg.Unpack()
			obj.Save(msg,obj.object)

class Message():
	def __init__(self,txhash=None):
		self.txhash = txhash
		self.protobuf = infiniti_pb2.Message()

	def Build(self, msg_type, obj, cK, app_id=APP_ID, version=MESSAGE_VERSION):
		if version == 10001:
			self.protobuf.message_type = msg_type
			self.protobuf.metadata = obj
			self.protobuf.application_id = app_id
			self.protobuf.version = version
			self.protobuf.issuer = cK.PublicKey()
			self.protobuf.issued = packTime()
			self.protobuf.signature = cK.Sign(hexlify(self.GetHash()))
			return self
	def TXHash(self):
		return self.txhash
	def MessageType(self):
		return self.protobuf.message_type
	def ApplicationId(self):
		return self.protobuf.application_id
	def Issuer(self):
		return self.protobuf.issuer
	def Issued(self):
		return self.protobuf.issued
	def Signature(self):
		return self.protobuf.signature
	def Version(self):
		return self.protobuf.version
	def Metadata(self):
		return self.protobuf.metadata
	def GetHash(self):
		tmp = self.Signature()
		self.protobuf.signature=''
		h = hashlib.sha3_256(self.protobuf.SerializeToString()).digest()
		self.protobuf.signature=tmp
		return h
	def isValid(self):
		if self.protobuf.version==10001:
			if self.protobuf.message_type == MESSAGES['create']:
				# Does the message already exist on disk?
				return self.isSignatureValid()
			elif self.protobuf.message_type == MESSAGES['update']:
				return self.isSignatureValid()
			elif  self.protobuf.message_type == MESSAGES['transfer']:
				return self.isSignatureValid()
			else:
				return False
	def isSignatureValid(self):
		# Does the indiciated issuer match the signature for this specific message?
		return Keyring().Verify(self.protobuf.signature, hexlify(self.GetHash()), Keyring().Address(prefix='Infiniti', cK=self.protobuf.issuer))
	def Serialize(self):
		return self.protobuf.SerializeToString()
	def Deserialize(self, msg):
		self.protobuf.ParseFromString(msg)
		return self
	def Commit(self,app):
		msg = self.Serialize()
		return commit_object(app,msg)
	def Unpack(self):
		if self.isValid():
			if self.MessageType() == infiniti_pb2.Message.CREATE:
				obj = ObjectMessage().Deserialize(self.Metadata())
				if obj.isValid():
					if obj.ObjectType() == infiniti_pb2.Object.IDENTITY:
						im = IdentityMessage().Deserialize(obj.Metadata())
						if im.PublicKey() == self.Issuer():
							im.name = obj.Name()
							im.object = obj
							return im
						else:
							return None
					elif obj.ObjectType() == infiniti_pb2.Object.FINGERPRINT:
						fp = FingerprintMessage().Deserialize(obj.Metadata())
						if fp.isValid():
							fp.object = obj
							return fp
						else:
							return None
					elif obj.ObjectType() == infiniti_pb2.Object.FILE:
						f = FileMessage().Deserialize(obj.Metadata())
						if f.isValid():
							f.object = obj
							return f
						else:
							return None
					elif obj.ObjectType() == infiniti_pb2.Object.LEDGER:
						pass
					elif obj.ObjectType() == infiniti_pb2.Object.CUSTOM:
						pass
				else:
					return None
			elif self.MessageType() == infiniti_pb2.Message.UPDATE:
				pass
			elif self.MessageType() == infiniti_pb2.Message.TRANSFER:
				pass
		else:
			return None
	def toJSON(self):
		obj = self.Unpack()
		i = LoadIdentityByPubkey(self.Issuer())
		if self.MessageType() == infiniti_pb2.Message.CREATE:
			return json.dumps({
				'txhash':hexlify(self.txhash),
				'type':'create',
				'app_id':hexlify(self.ApplicationId()),
				'version':self.Version(),
				'issuer':i.toJSON(),
				'object':obj.toJSON(),
			})
		elif self.MessageType() == infiniti_pb2.Message.UPDATE:
			msg_type = "update"
		elif self.MessageType() == infiniti_pb2.Message.TRANSFER:
			msg_type = "transfer"

class ObjectMessage():
	def __init__(self):
		self.protobuf = infiniti_pb2.Object()
	def Build(self, name, obj, obj_type, issue_mode, encryption=ENCRYPTION['none'], enc_key = None, version=OBJECT_VERSION):
		if version == 10001:
			self.protobuf.version = version
			self.protobuf.name = name
			self.protobuf.metadata = obj
			self.protobuf.issue_mode = issue_mode
			self.protobuf.object_type = obj_type
			self.protobuf.id = self.GetHash()
			self.protobuf.encryption = encryption
			if self.protobuf.encryption == ENCRYPTION['none']:
				self.protobuf.encryption_key = ''
				self.isEncrypted = False
			else:
				if enc_key is None:
					assert "Key needed to decrypt encrypted object!"
				self.key = enc_key
				if self.protobuf.encryption == ENCRYPTION['aes']:
					self.protobuf.metadata = self.key.AESEncrypt(self.protobuf.metadata)
				elif self.protobuf.encryption == ENCRYPTION['rsa']:
					self.protobuf.metadata = self.key.RSAEncrypt(self.protobuf.metadata,enc_key)
				elif self.protobuf.encryption == ENCRYPTION['elgamal']:
					self.protobuf.encryption_key = self.key.PublicKey()
				self.isEncrypted = True
			return self
	def Name(self):
		return self.protobuf.name
	def IssueMode(self):
		return self.protobuf.issue_mode
	def ObjectType(self):
		return self.protobuf.object_type
	def Id(self):
		return self.GetHash()
	def Encryption(self):
		return self.protobuf.encryption
	def EncryptionKey(self):
		return self.protobuf.encryption_key
	def Version(self):
		return self.protobuf.version
	def Metadata(self):
		return self.protobuf.metadata
	def isValid(self):
		if self.protobuf.object_type == OBJECT_TYPE['identity']:
			if self.protobuf.issue_mode == ISSUE_MODE['none']:
				i = IdentityMessage().Deserialize(self.protobuf.metadata)
				return i.isValid()
			else:
				return False
		elif self.protobuf.object_type == OBJECT_TYPE['fingerprint']:
			if self.protobuf.issue_mode == ISSUE_MODE['none']:
				fp = FingerprintMessage().Deserialize(self.protobuf.metadata)
				return fp.isValid()
			else:
				return False
		elif self.protobuf.object_type == OBJECT_TYPE['ledger']:
			if self.protobuf.issue_mode == ISSUE_MODE['once'] or self.protobuf.issue_mode == ISSUE_MODE['multi']:
				le = LedgerMessage().Deserialize(self.protobuf.metadata)
				return le.isValid()
			else:
				return False
		elif self.protobuf.object_type == OBJECT_TYPE['custom']:
			# Custom objects are always valid
			return True
		else:
			return False
	def GetHash(self):
		return hashlib.sha3_256(self.protobuf.SerializeToString()).digest()
	def Serialize(self):
		if not self.isEncrypted and self.protobuf.encryption != ENCRYPTION['none']:
			if self.protobuf.encryption == ENCRYPTION['aes']:
				self.protobuf.metadata = self.key.AESEncrypt(self.protobuf.metadata)
			elif self.protobuf.encryption == ENCRYPTION['rsa']:
				self.protobuf.metadata = self.key.RSAEncrypt(self.protobuf.metadata)
			elif self.protobuf.encryption == ENCRYPTION['elgamal']:
				self.protobuf.metadata = self.key.ElGamalEncrypt(self.protobuf.metadata)
			self.isEncrypted = True
		return self.protobuf.SerializeToString()
	def Deserialize(self, msg, key=None):
		self.key = key
		self.protobuf = infiniti_pb2.Object()
		self.protobuf.ParseFromString(msg)
		self.isEncrypted = False
		if self.protobuf.encryption == ENCRYPTION['aes']:
			if key is None:
				assert "Key needed to decrypt encrypted object!"
			self.protobuf.metadata = self.key.AESDecrypt(self.protobuf.metadata)
		elif self.protobuf.encryption == ENCRYPTION['rsa']:
			if key is None:
				assert "Key needed to decrypt encrypted object!"
			self.protobuf.metadata = self.key.RSADecrypt(self.protobuf.metadata)
		elif self.protobuf.encryption == ENCRYPTION['elgamal']:
			if key is None:
				assert "Key needed to decrypt encrypted object!"
			self.protobuf.metadata = self.key.ElGamalDecrypt(self.protobuf.metadata)
		return self

class IdentityMessage():
	def __init__(self,i=None, version=ID_VERSION):
		if version == 10001:
			self.protobuf = infiniti_pb2.Identity()
			self.protobuf.version = version
			if i is not None:
				self.identity = i
				self.protobuf.public_key = self.identity.Key().PublicKey()
				self.protobuf.fingerprint = self.identity.Fingerprint()
				self.protobuf.rsa_public_key = self.identity.Key().RSAPublic()
	def RSAPublicKey(self):
		return self.protobuf.rsa_public_key
	def PublicKey(self):
		return self.protobuf.public_key
	def Version(self):
		return self.protobuf.version
	def Fingerprint(self):
		return self.protobuf.fingerprint
	def Deserialize(self, msg):
		self.protobuf = infiniti_pb2.Identity()
		self.protobuf.ParseFromString(msg)
		return self
	def Serialize(self):
		return self.protobuf.SerializeToString()
	def isValid(self):
		return (self.protobuf.version > 0) and (len(self.protobuf.fingerprint) > 0)
	def GetHash(self):
		protobuf = infiniti_pb2.Identity()
		protobuf.version = self.Version()
		protobuf.fingerprint = self.Fingerprint()
		return hashlib.sha3_256(protobuf.SerializeToString()).digest()
	def Save(self,msg,obj,i=None):
		return SaveIdentityMessage(msg,obj,self,i)
	def Timestamp(self):
		return self.timestamp
	def Name(self):
		return self.name
	def isLocal(self):
		return self.local == 1
	def Load(self,fp):
		data = LoadIdentity(fp)
		if data is None:
			return None
		else:
			self.protobuf.fingerprint = str(data[0])
			self.protobuf.version = data[1]
			self.protobuf.public_key = str(data[2])
			self.protobuf.rsa_public_key = data[3]
			self.name = data[4]
			self.timestamp = unpackTime(data[5])
			self.local = data[6]
		return self
	def toJSON(self):
		return {
			'hash':hexlify(self.GetHash()),
			'version':self.Version(),
			'fingerprint':hexlify(self.Fingerprint()),
			'name':self.Name(),
			'timestamp':str(self.Timestamp()),
			'local':self.isLocal(),
		}

class FingerprintMessage():
	def __init__(self, k=None, version=FINGERPRINT_VERSION):
		if k is not None:
			self.key = k
			if version == 10001:
				self.protobuf = infiniti_pb2.Fingerprint()
				self.protobuf.version = version
				self.protobuf.fingerprint = hexlify(self.key.Fingerprint())
				self.protobuf.public_key = hexlify(self.key.PublicKey())
				self.protobuf.rsa_public_key = self.key.RSAPublic()
	def RSAPublicKey(self):
		return self.protobuf.rsa_public_key
	def isValid(self):
		return (self.protobuf.version > 0) and (len(self.protobuf.fingerprint) > 0) and (len(self.protobuf.public_key) > 0)
	def Serialize(self):
		return self.protobuf.SerializeToString()
	def Deserialize(self, msg):
		self.protobuf = infiniti_pb2.Fingerprint()
		self.protobuf.ParseFromString(msg)
		return self
	def Fingerprint(self):
		return unhexlify(self.protobuf.fingerprint)
	def PublicKey(self):
		return unhexlify(self.protobuf.public_key)
	def GetHash(self):
		return self.key.GetHash()
	def Save(self,msg,obj):
		return SaveFingerprintMessage(msg,obj,self)
	def Version(self):
		return self.protobuf.version
	def toJSON(self):
		return json.dumps({
			'hash':hexlify(self.GetHash()),
			'version':self.Version(),
			'fingerprint':hexlify(self.Fingerprint()),
			'pubkey':hexlify(self.PublicKey()),
			'rsa_pubkey':self.RSAPublicKey(),
			'addresses': {
				'bitcoin':Keyring().Address(prefix='Bitcoin', cK=self.PublicKey()),
				'ethereum':Keyring().Address(prefix='Ethereum', cK=self.PublicKey()),
				'tao':Keyring().Address(prefix='Tao', cK=self.PublicKey()),
				'infiniti':Keyring().Address(prefix='Infiniti', cK=self.PublicKey()),
			},
		})

class FileMessage():
	def __init__(self,address,name,file_type,comment, encryption=ENCRYPTION['none'], enc_key = None,version=FILE_VERSION):
		if version == 10001:
			self.protobuf = infiniti_pb2.File()
			self.protobuf.address = address
			self.protobuf.version = version
			self.protobuf.name = name
			self.protobuf.comment = comment
			self.protobuf.file_type = file_type
			self.protobuf.encryption = encryption
			if self.protobuf.encryption == ENCRYPTION['none']:
				self.protobuf.encryption_key = ''
				self.isEncrypted = False
			else:
				if enc_key is None:
					assert "Key needed to decrypt encrypted object!"
				self.key = enc_key
				if self.protobuf.encryption == ENCRYPTION['aes']:
					self.protobuf.metadata = self.key.AESEncrypt(self.protobuf.metadata)
				elif self.protobuf.encryption == ENCRYPTION['rsa']:
					self.protobuf.metadata = self.key.RSAEncrypt(self.protobuf.metadata,enc_key)
				elif self.protobuf.encryption == ENCRYPTION['elgamal']:
					self.protobuf.encryption_key = self.key.PublicKey()
				self.isEncrypted = True

	def Address(self):
		return self.protobuf.address

	def Name(self):
		return self.protobuf.name

	def Comment(self):
		return self.protobuf.comment

	def FileType(self):
		return self.protobuf.file_type

	def Version(self):
		return self.protobuf.version

	def Deserialize(self, msg):
		self.protobuf = infiniti_pb2.File()
		self.protobuf.ParseFromString(msg)
		return self

	def Serialize(self):
		return self.protobuf.SerializeToString()

	def Encryption(self):
		return self.protobuf.encryption
	def EncryptionKey(self):
		return self.protobuf.encryption_key
	def GetHash(self):
		return hashlib.sha3_256(self.protobuf.SerializeToString()).digest()

	def isValid(self):
		return (self.protobuf.version > 0)

	def Save(self,msg,obj):
		return SaveFileMessage(msg,obj,self)
	def toJSON(self):
		pass
		# TODO

class LedgerMessage():
	def __init__(self, issue_amount, number_of_decimals, shortname, issue_expires, version=LEDGER_VERSION):
		if version == 10001:
			self.protobuf = infiniti_pb2.Object()
			self.protobuf.version = version
			self.protobuf.issue_amount = issue_amount
			self.protobuf.number_of_decimals = number_of_decimals
			self.protobuf.shortname = shortname
			self.protobuf.issue_expires = issue_expires

	def GetHash(self):
		return hashlib.sha3_256(self.protobuf.SerializeToString()).digest()

	def NumberOfDecimals(self):
		return self.protobuf.number_of_decimals

	def Version(self):
		return self.protobuf.version

	def IssueAmount(self):
		return self.protobuf.issue_amount

	def Abbreviation(self):
		return self.protobuf.shortname

	def IssueExpires(self):
		return self.protobuf.issue_expires

	def isValid(self):
		return (self.Version() > 0) and (self.IssueAmount() >= 1) and (self.NumberOfDecimals() >= 0) and (len(self.Abbreviation()) > 0) and (unpackTime(self.IssueExpires()) > 0) and not self.isIssueExpired()

	def Serialize(self):
		return self.protobuf.SerializeToString()

	def Deserialize(self, msg):
		self.protobuf = infiniti_pb2.Ledger()
		self.protobuf.ParseFromString(msg)
		return self

	def isIssueExpired(self):
		return (unpackTime(self.IssueExpires()) <= time.time())

class TransferMessage():
	class Input():
		def __init__(self):
			self.protobuf = infiniti_pb2.Transfer()
			self.protobuf.version = TRANSFER_VERSION

	class Output():
		def __init__(self):
			pass

	def GetHash(self):
		return hashlib.sha3_256(self.protobuf.SerializeToString()).digest()

class NewsMessage():
	def __init__(self, title=None, content=None, debug = False, version=NEWS_VERSION):
		if title is not None:
			if version == 10001:
				self.protobuf = infiniti_pb2.News()
				self.protobuf.title = title
				self.protobuf.image = image
				self.protobuf.content = content
				self.protobuf.debug = debug

	def Load(self,obj_id):
		data = LoadNewsItem(obj_id)			

	def Image(self):
		return self.protobuf.image

	def GetHash(self):
		return hashlib.sha3_256(self.protobuf.SerializeToString()).digest()

	def isValid(self):
		# Infiniti Protocol news can only come from the Infiniti Protocol Master identity
		# The Master identity has two functions: issue news items and collect donations.
		return GetNewsAuthor() == unhexlify('035ca2cd233d78040f4067f56714cff5a12a4218f6b778c96f9626ed1ed6f62b4b')

	def Title(self):
		return self.protobuf.title

	def Content(self):
		return self.protobuf.content

	def Debug(self):
		return self.protobuf.debug > -1
