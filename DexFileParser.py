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
                return self.getClassByIdx( idx ).getName()

        def getTypeByIdx(self, idx):
                return self._dex.typeiditems[idx]

        def getTypeNameByIdx(self, idx):
                return self.getTypeByIdx( idx ).getName()


class DexFile:
        def __init__(self, data):
                self._data = data
                self._resolver = ObjResolver( self )
                self._parse( data )
                
                #just preventing DoS attacks
                assert( self.class_defs_size < 100000 )
                assert( self.string_ids_size < 100000 )
                assert( self.type_ids_size   < 100000 )

                self.classdefitems =   { idx:class_def_item( self._resolver, data, offset ) for (idx,offset) in map(lambda idx: (idx,self.class_defs_off+(32*idx)), range( self.class_defs_size )) }
                self.stringiditems =   { idx:string_id_item( self._resolver, data, offset ) for (idx,offset) in map(lambda idx: (idx,self.string_ids_off+(4*idx)), range( self.string_ids_size )) }
                self.stringdataitems = { offset:string_data_item( self._resolver, data, offset ) for offset  in map(lambda iditem: iditem['string_data_off'], self.stringiditems.values()) }
                self.typeiditems =     { idx:type_id_item( self._resolver, data, offset ) for (idx,offset)   in map(lambda idx: (idx,self.type_ids_off+(4*idx)), range( self.type_ids_size )) }
                self.methoditems =     { idx:method_id_item( self._resolver, data, offset ) for (idx,offset) in map(lambda idx: (idx,self.method_ids_off+(8*idx)), range( self.method_ids_size )) }

        def _parse(self, data):
                assert( 104 <= len( data ) )
                (self.magic, self.checksum, self.signature) = struct.unpack_from( '8sI20s', data, 0 )
                (self.string_ids_size, self.string_ids_off) = struct.unpack_from( 'II', data, 56 )
                (self.type_ids_size, self.type_ids_off)     = struct.unpack_from( 'II', data, 64 )
                (self.class_defs_size, self.class_defs_off) = struct.unpack_from( 'II', data, 96 )
                (self.method_ids_size, self.method_ids_off) = struct.unpack_from( 'II', data, 88 )


        def fixChecksum(self):
                struct.pack_into( 'I', self._data, 8, (zlib.adler32( self._data[12:],1 ) % (2**32)) )

        def setSignature(self, signature):
                assert( len(signature) == 40 )
                sig = []
                for i in range(20):
                        sig.append( int( signature[i*2:(i*2)+2], 16 ) )
                struct.pack_into( 'B'*20, self._data, 12, *sig )


class DexHeaderObj(dict):
        def __init__(self, resolver, data, offset):
                dict.__init__(self)
                self._resolver = resolver
                self._offset = offset
                self._data = data
                self._fmt = []

        def _easyParser(self, data, offset, layout):
                pos = offset
                for (key, fmt_str) in layout:
                        size = struct.Struct( fmt_str ).size
                        assert( pos+size <= len( data ) )
                        (self[key],) = struct.unpack_from( fmt_str, data, pos )
                        pos += size

        def _parse( self, data, offset ):
                self._easyParser( data, offset, self._fmt )

        def _parseULEB128(self, data, offset):
                def isHighBitSet(byte):
                        return (byte & 0x80) == 0x80

                assert( offset+5 <= len(data) )
                (byte0, byte1, byte2, byte3, byte4) = struct.unpack_from( 'BBBBB', data, offset )
                value = (byte0 & 0x7f)
                bytelen = 1
                if isHighBitSet( byte0 ):
                        bytelen += 1
                        value = (value & 0xff) | ((byte1 & 0x7f)<<7)
                        if isHighBitSet( byte1 ):
                                bytelen += 1
                                value = (value & 0xffff) | ((byte2 & 0x7f)<<14)
                                if isHighBitSet( byte2 ):
                                        bytelen += 1
                                        value = (value & 0xffffff) | ((byte3 & 0x7f)<<21)
                                        if isHighBitSet( byte3 ):
                                                bytelen += 1
                                                value = (value & 0xffffffff) | ((byte4 & 0x7f)<<28)
                value = (value & 0xffffffff) #make sure it is only 32bit long
                return (value, bytelen)


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
                assert( int(value) >= 0 and int( value ) <= 0xffffffff )
                self['access_flags'] = value
                struct.pack_into( 'I', self._data, self._offset+4, value )

        def getName(self):
                return self._resolver.getTypeNameByIdx( self['class_idx'] )

        def getClassData(self):
                return class_data_item( self._resolver, self._data, self['class_data_off'] )


class class_data_item(DexHeaderObj):
        def __init__(self, resolver, data, offset):
                DexHeaderObj.__init__( self, resolver, data, offset )
                self._fmt = []
                self._parse( data )

        def _parse(self, data):
                pos = 0
                (value, bytelen) = self._parseULEB128( data, self._offset+pos )
                self['static_fields_size'] = value
                pos += bytelen
                (value, bytelen) = self._parseULEB128( data, self._offset+pos )
                self['instance_fields_size'] = value
                pos += bytelen
                (value, bytelen) = self._parseULEB128( data, self._offset+pos )
                self['direct_methods_size'] = value
                pos += bytelen
                (value, bytelen) = self._parseULEB128( data, self._offset+pos )
                self['virtual_methods_size'] = value
                pos += bytelen

                offset = self._offset+pos
                self['static_fields'] = {} 
                for idx in range( self['static_fields_size'] ):
                        self['static_fields'][idx] = encoded_field( self._resolver, data, offset )
                        offset += self['static_fields'][idx].getLen()

                self['instance_fields'] = {} 
                for idx in range( self['instance_fields_size'] ):
                        self['instance_fields'][idx] = encoded_field( self._resolver, data, offset )
                        offset += self['instance_fields'][idx].getLen()

                self['direct_methods'] = {} 
                for idx in range( self['direct_methods_size'] ):
                        self['direct_methods'][idx] = encoded_method( self._resolver, data, offset )
                        offset += self['direct_methods'][idx].getLen()

                self['virtual_methods'] = {} 
                for idx in range( self['virtual_methods_size'] ):
                        self['virtual_methods'][idx] = encoded_method( self._resolver, data, offset )
                        offset += self['virtual_methods'][idx].getLen()

        def getDirectEncodedMethod(self, wanted_idx):
                cur = 0
                for idx in range( self['direct_methods_size'] ):
                        method = self['direct_methods'][idx]
                        cur += method['method_idx_diff']
                        if cur > wanted_idx:
                                return None #no method in this class with this index
                        if cur == wanted_idx:
                                return method
                return None

        def getVirtualEncodedMethod(self, idx):
                cur = 0
                for idx in range( self['virtual_methods_size'] ):
                        method = self['virtual_methods'][idx]
                        cur += method['method_idx_diff']
                        if cur > wanted_idx:
                                return None #no method in this class with this index
                        if cur == wanted_idx:
                                return method
                return None


class encoded_field(DexHeaderObj):
        def __init__(self, resolver, data, offset):
                DexHeaderObj.__init__( self, resolver, data, offset )
                self._fmt = []
                self._parse( data )

        def _parse(self, data):
                self.len = 0
                (value, bytelen) = self._parseULEB128( data, self._offset+self.len )
                self['field_idx_diff'] = value
                self.len += bytelen
                (value, bytelen) = self._parseULEB128( data, self._offset+self.len )
                self['access_flags'] = value
                self.len += bytelen

        def getLen(self):
                return self.len


class encoded_method(DexHeaderObj):
        def __init__(self, resolver, data, offset):
                DexHeaderObj.__init__( self, resolver, data, offset )
                self._fmt = []
                self._parse( data )

        def _parse(self, data):
                self.len = 0
                (value, bytelen) = self._parseULEB128( data, self._offset+self.len )
                self['method_idx_diff'] = value
                self.len += bytelen
                (value, bytelen) = self._parseULEB128( data, self._offset+self.len )
                self['access_flags'] = value
                self.len += bytelen
                (value, bytelen) = self._parseULEB128( data, self._offset+self.len )
                self['code_off'] = value
                self.len += bytelen

        def getLen(self):
                return self.len

        def getCodeItem(self):
                return code_item( self._resolver, self._data, self['code_off'] )


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
                (size, bytelen) = self._parseULEB128( data, self._offset )
                self['utf16_size'] = size
                assert( self._offset+bytelen+self['utf16_size'] <= len(data) )
                self['data'] = ''.join( struct.unpack_from( 's'*self['utf16_size'], data, self._offset+bytelen ) )


class type_id_item(DexHeaderObj):
        def __init__(self, resolver, data, offset):
                DexHeaderObj.__init__( self, resolver, data, offset )
                self._fmt = [
                        ('descriptor_idx','I'),
                       ]
                self._parse( data, offset )

        def getName(self):
                return self._resolver.getStringByIdx(self['descriptor_idx'])


class method_id_item(DexHeaderObj):
        def __init__(self, resolver, data, offset):
                DexHeaderObj.__init__( self, resolver, data, offset )
                self._fmt = [
                        ('class_idx','H'),
                        ('proto_idx','H'),
                        ('name_idx','I'),
                       ]
                self._parse( data, offset )

        def getName(self):
                return self._resolver.getStringByIdx(self['name_idx'])


class code_item(DexHeaderObj):
        def __init__(self, resolver, data, offset):
                DexHeaderObj.__init__( self, resolver, data, offset )
                self._fmt = [
                        ('registers_size','H'),
                        ('ins_size','H'),
                        ('outs_size','H'),
                        ('tries_size','H'),
                        ('debug_info_off','I'),
                        ('insns_size','I'),
                        ]
                self._parse( data, offset )
                self._insOffset = offset + struct.calcsize(''.join(map(lambda x: x[1], self._fmt)))
                self._parseCode()
                #extend to padding, tries and handlers

        def _parseCode(self):
                self['insns'] = struct.unpack_from( 'B'*2*self['insns_size'], self._data, self._insOffset )

        def getCode(self):
                return self['insns']

        def setCode(self, ins):
                insout = map(ord, ins)
                struct.pack_into( 'B'*min( self['insns_size']*2, len(ins) ), self._data, self._insOffset, *insout )



if __name__ == "__main__":
        if not len(sys.argv) == 2:
                print "USAGE: %s <dexfile>"%sys.argv[0]
                exit(1)
        filename = sys.argv[1]
        data = array.array('c', open(filename, 'rb').read() )
        dexfile = DexFile(data)
        dexfile.fixChecksum()
        file(filename, 'wb').write(dexfile._data)

