from hashlib import sha256
import hashlib,sha3
import binascii, time, datetime
from datetime import datetime
from Crypto.Hash import HMAC
from struct import pack

class PRNG(object):

  def __init__(self, seed):
    self.index = 0
    self.seed = HMAC.new(seed + b"Infiniti Protocol").digest()
    self.buffer = b""

  def __call__(self, n):
    while len(self.buffer) < n:
        self.buffer += HMAC.new(self.seed +
                                pack("<I", self.index)).digest()
        self.index += 1
    result, self.buffer = self.buffer[:n], self.buffer[n:]
    return result

def hasher(string,fingerprint=False):
	if fingerprint:
		y = 1000
	else:
		y = 15000
	for x in range(0,y):
		string = hashlib.sha3_256(string).digest()
	return string

def packTime(_time=time.time()):
    return binascii.unhexlify(str(int(time.mktime(time.gmtime(_time))) - time.timezone))

def unpackTime(_time):
    return datetime.utcfromtimestamp(int(binascii.hexlify(_time)))

