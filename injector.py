#!/usr/bin/env python
# Copyright (C) 2012 thuxnder@dexlabs.org
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import array
import struct
import zlib
import sys

class DexMethod:
	def __init__(self, dexfile, offset):
		self._dexfile = dexfile
		self._offset = offset
		self._registers_size = 0
		self._insns_size = 0
		if offset > 0:
			self._parseHeader()

	def _parseHeader(self):
		(self._registers_size, ) = self._dexfile.getData(self._offset, 2, 'H')
		(self._insns_size, )   = self._dexfile.getData(self._offset+12, 4, 'I')

	def getMethodSize(self):
		return self._insns_size*2

	def obfuscate(self, obfuscator):
		if self._offset == 0:
			return False
		if len(obfuscator) > self._insns_size*2: #wordsize
			raise Exception("method too short, cannot insert bytecode")
		bytecode = self._dexfile.getData(self._offset+16, len(obfuscator), 'B'*len(obfuscator))
		if not reduce(lambda op1,op2: op1 and op2, map(lambda byte: byte==0x00, bytecode)):
			raise Exception("not enough space to inject obfuscator")
		bytecode = list(bytecode)
		bytecode = map(lambda (orig,patch): ord(patch), zip(bytecode, obfuscator))
		self._dexfile.setData(self._offset+16, len(bytecode), 'B'*len(bytecode), bytecode)
		if self._registers_size == 0:
			self._dexfile.setData( self._offset, 2, 'H', (0x01,) )
		return True

class DexClass:
	def __init__(self, dexfile, offset):
		self._dexfile = dexfile
		self._offset = offset
		self._directMethods = {}
		self._virtualMethods = {}
		self._parseHeader()
		if self._class_data_off > 0:
			self._parseClassDataItem()

	def hasData(self):
		return self._class_data_off > 0

	def setVerified(self):
		self._dexfile.setData(self._offset+4, 4, 'I', (self._access_flags|0x10000,) )

	def _parseHeader(self):
		(self._access_flags, )   = self._dexfile.getData(self._offset+4, 4, 'I')
		(self._class_data_off, ) = self._dexfile.getData(self._offset+24, 4, 'I')

	def _parseClassDataItem(self):
		offset = self._class_data_off
		(size, self.static_filds_size) = self._dexfile.parseUleb128(offset)
		offset += size
		(size, self.instance_fields_size) = self._dexfile.parseUleb128(offset)
		offset += size
		(size, self.direct_methods_size)  = self._dexfile.parseUleb128(offset)
		offset += size
		(size, self.virtual_methods_size) = self._dexfile.parseUleb128(offset)
		offset += size

		#skip encode fields
		for i in range( (self.static_filds_size+self.instance_fields_size)*2 ):
			(size, tmp) = self._dexfile.parseUleb128(offset)
			offset += size
		
		self._direct_methods_offset_list = []
		for i in range( self.direct_methods_size ):
			(size, method_idx_diff) = self._dexfile.parseUleb128(offset)
			offset += size
			(size, access_flags) = self._dexfile.parseUleb128(offset)
			offset += size
			(size, code_off) = self._dexfile.parseUleb128(offset)
			offset += size
			if code_off == 0: #abstract or native
				continue
			self._direct_methods_offset_list.append(code_off)
		self._directMethods = { off: self._dexfile.createMethod(off) for off in self._direct_methods_offset_list }

		self._virtual_methods_offset_list = []
		for i in range( self.virtual_methods_size ):
			(size, method_idx_diff) = self._dexfile.parseUleb128(offset)
			offset += size
			(size, access_flags) = self._dexfile.parseUleb128(offset)
			offset += size
			(size, code_off) = self._dexfile.parseUleb128(offset)
			offset += size
			if code_off == 0: #abstract or native
				continue
			self._virtual_methods_offset_list.append(code_off)
		self._virtualMethods = { off: self._dexfile.createMethod(off) for off in self._virtual_methods_offset_list }

	def getMethods(self):
		return self._directMethods.values()+self._virtualMethods.values()
		

class Dexfile:
	def __init__(self, filename):
		self._dexfile = filename
		self._data = array.array('c', open(self._dexfile, 'rb').read() )

	def getData(self, offset, size, form):
		if len(self._data) < offset+size:
			raise Exception("dexfile is too small")
		return struct.unpack_from(form, self._data, offset)

	def setData(self, offset, size, form, data):
		if len(self._data) < offset+size:
			raise Exception("dexfile is too small")
		return struct.pack_into(form, self._data, offset, *data)

	def save(self):
		self._fixChecksum()
		dexfile = open(self._dexfile, 'wb')
		dexfile.write(self._data)
		dexfile.close()

	def parseUleb128(self, offset):
		(byte0, byte1, byte2, byte3) = self.getData(offset, 4, 'BBBB')
		size = (byte0 & 0x7f)
		bytelen = 1
		if (byte0 & 0x80) == 0x80:
			bytelen += 1
			size = (size & 0xff) | ((byte1 & 0x7f)<<7)
			if (byte1 & 0x80) == 0x80:
				bytelen += 1
				size = (size & 0xffff) | ((byte2 & 0x7f)<<14)
				if (byte2 & 0x80) == 0x80:
					bytelen += 1
					size = (size & 0xffffff) | ((byte3 & 0x7f)<<21)
		return (bytelen, size)

	def createClass(self, offset):
		return DexClass(self, offset)

	def getClasses(self):
		(clsCount, offset) = self.getData(96, 8, 'II')
		classOffList =  map(lambda idx: offset+(32*idx), range(clsCount))
		self._classes = { offset:self.createClass(offset) for offset in classOffList }
		return self._classes.values()

	def createMethod(self, offset):
		return DexMethod(self, offset)

	def _fixChecksum(self):
		self.setData(8, 4, 'I', (zlib.adler32(self._data[12:],1)% (2**32),))

	def _setSignature(self, signature):
		if not len(signature) == 40:
			raise Exception("wrong signature size")
		sig = []
		for i in range(20):
			sig.append( int(signature[i*2:(i*2)+2], 16) )
		self.setData(12, 20, 'B'*20, sig)


class FileInjector:
	def __init__(self, filename):
		self._dexfile = Dexfile(filename)
		self._parseClassList()
		self._parseMethodList()
	

	def _parseClassList(self):
		def pos(x):
			return x>0

		(size, offset) = self._dexfile.getData(96, 8, 'II')
		classes = self._dexfile.getClasses()
		self._classes = filter(lambda cls: cls.hasData(), classes)
	
	def _parseMethodList(self):
		self._methods = { cls:cls.getMethods() for cls in self._classes}

	def obfuscate(self):
		for cls, methods in self._methods.items():
			if reduce(lambda op1,op2: op1 or op2, map(self._obfuscator_arrayDataOverlayIf, methods), False):
				cls.setVerified()
		self._dexfile._setSignature("ee402b187725a2955b913d058edabe704122c6e0")
		self._dexfile.save()


	def _obfuscator_arrayDataOverlayIf(self, method):
		obfuscator = array.array('c', "\x32\x00\x09\x00\x26\x00\x03\x00\x00\x00\x00\x03\x01\x00\x00\x00\x00\x00")
		size = method.getMethodSize()
		if size == 0:
			print "skip method @ 0x%x" % method._offset
			return 
		payloadlen = size-len(obfuscator)
		struct.pack_into('I', obfuscator, 14, payloadlen)
		return method.obfuscate(obfuscator)







if __name__ == "__main__":
	filename = sys.argv[1]
	inj = FileInjector(filename)
	inj.obfuscate()





