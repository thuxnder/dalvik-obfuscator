#!/usr/bin/env python
#
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

import sys
import struct
import zlib
import array

class ObjResolver:
	def __init__(self, dexfile):
		self._dex = dexfile

	#TODO mutf8 translation
	def getStringByIdx(self, idx):
		return self._dex.stringdataitems[ self._dex.stringiditems[idx]['string_data_off'] ]['data']

	def getClassByIdx(self, idx):
		return self._dex.classdefitems[idx]

	def getClassNameByIdx(self, idx):
		return self.getClassByIdx(idx).getName()

	def getTypeByIdx(self, idx):
		return self._dex.typeiditems[idx]

	def getTypeNameByIdx(self, idx):
		return self.getTypeByIdx(idx).getName()

class DexFile:
	def __init__(self, data):
		self._data = data
		self._resolver = ObjResolver(self)
		self._parse(data)
		
		#just preventing DoS attacks
		assert( self.class_defs_size < 100000 )
		assert( self.string_ids_size < 100000 )
		assert( self.type_ids_size   < 100000 )

		self.classdefitems = { idx:class_def_item(self._resolver, data, offset) for (idx,offset) in map(lambda idx: (idx,self.class_defs_off+(32*idx)), range(self.class_defs_size)) }
		self.stringiditems = { idx:string_id_item(self._resolver, data, offset) for (idx,offset) in map(lambda idx: (idx,self.string_ids_off+(4*idx)), range(self.string_ids_size)) }
		self.stringdataitems = { offset:string_data_item(self._resolver, data, offset) for offset in map(lambda iditem: iditem['string_data_off'], self.stringiditems.values()) }
		self.typeiditems = { idx:type_id_item(self._resolver, data, offset) for (idx,offset) in map(lambda idx: (idx,self.type_ids_off+(4*idx)), range(self.type_ids_size)) }

	def _parse(self, data):
		assert( 104 <= len(data) )
		(self.magic, self.checksum, self.signature) = struct.unpack_from('8sI20s', data, 0)
		(self.string_ids_size, self.string_ids_off) = struct.unpack_from('II', data, 56)
		(self.type_ids_size, self.type_ids_off) = struct.unpack_from('II', data, 64)
		(self.class_defs_size, self.class_defs_off) = struct.unpack_from('II', data, 96)


	def fixChecksum(self):
		struct.pack_into('I', self._data, 8, (zlib.adler32(self._data[12:],1)% (2**32)))

	def setSignature(self, signature):
		assert( len(signature) == 40 )
		sig = []
		for i in range(20):
			sig.append( int(signature[i*2:(i*2)+2], 16) )
		struct.pack_into('B'*20, self._data, 12, *sig)

class DexHeaderObj(dict):
	def __init__(self, resolver, data, offset):
		dict.__init__(self)
		self._resolver = resolver
		self._offset = offset
		self._data = data
		self._fmt = []

	def _easyParser(self, data, layout):
		pos = self._offset
		for (key, fmt_str) in layout:
			size = struct.Struct(fmt_str).size
			assert( pos+size <= len(data) )
			(self[key],) = struct.unpack_from( fmt_str, data, pos )

	def _parse( self, data, offset ):
		self._easyParser( data, self._fmt )

class class_def_item(DexHeaderObj):
	def __init__(self, resolver, data, offset):
		DexHeaderObj.__init__( self, resolver, data, offset )
		self._fmt = [ 
			('class_idx','I'),
			('access_flags','I'),
			('superclass_idx','I'),
			('interfaces_off','I'),
			('source_file_idx','I'),
			('annotations_off','I'),
			('class_data_off','I'),
			('static_values_off','I'),
		      ]
		self._parse( data, offset )

	def getFlags(self):
		return self['access_flags']

	def setFlags(self, value):
		assert( int(value) >= 0 and int(value) <= 0xffffffff )
		self['access_flags'] = value
		struct.pack_into('I', self._data, self._offset+4, value)

	def getName(self):
		return self._resolver.getTypeNameByIdx( self['class_idx'] )


class string_id_item(DexHeaderObj):
	def __init__(self, resolver, data, offset):
		DexHeaderObj.__init__( self, resolver, data, offset )
		self._fmt = [
			('string_data_off','I'),
		       ]
		self._parse( data, offset )

class string_data_item(DexHeaderObj):
	def __init__(self, resolver, data, offset):
		DexHeaderObj.__init__( self, resolver, data, offset )
		self._parse( data )

	def _parse(self, data):
		assert( self._offset+4 <= len(data) )
		(byte0, byte1, byte2, byte3) = struct.unpack_from('BBBB', data, self._offset)
		self['utf16_size'] = (byte0 & 0x7f)
		bytelen = 1
		if (byte0 & 0x80) == 0x80:
			bytelen += 1
			self['utf16_size'] = (self['utf16_size'] & 0xff) | ((byte1 & 0x7f)<<7)
			if (byte1 & 0x80) == 0x80:
				bytelen += 1
				self['utf16_size'] = (self['utf16_size'] & 0xffff) | ((byte2 & 0x7f)<<14)
				if (byte2 & 0x80) == 0x80:
					bytelen += 1
					self['utf16_size'] = (self['utf16_size'] & 0xffffff) | ((byte3 & 0x7f)<<21)
		assert( self._offset+bytelen+self['utf16_size'] <= len(data) )
		self['data'] = ''.join( struct.unpack_from('s'*self['utf16_size'], data, self._offset+bytelen) )

class type_id_item(DexHeaderObj):
	def __init__(self, resolver, data, offset):
		DexHeaderObj.__init__( self, resolver, data, offset )
		self._fmt = [
			('descriptor_idx','I'),
		       ]
		self._parse( data, offset )

	def getName(self):
		return self._resolver.getStringByIdx(self['descriptor_idx'])



if __name__ == "__main__":
	if not len(sys.argv) == 4:
		print "USAGE: %s <dexfile> <class idx> <flag as hex value>"%sys.argv[0]
		exit(1)
	filename = sys.argv[1]
	cls = int(sys.argv[2])
	flag = int(sys.argv[3],16)
	data = array.array('c', open(filename, 'rb').read() )
	dexfile = DexFile(data)
	dexfile.classdefitems[cls].setFlags(flag)
	dexfile.setSignature("ee402b187725a2955b913d058edabe704122c6e0")
	dexfile.fixChecksum()
	file(filename, 'wb').write(dexfile._data)

