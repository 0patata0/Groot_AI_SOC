#!/usr/bin/env python3
"""Read Thor ELF metadata without loading a module or relying on kmod's old layout.

Supports AArch64 ELF64 little endian ET_REL, compact next/crc/name imports,
PREL32 kernel_symbol exports and absolute u32 CRC tables. Other layouts fail.
"""
import argparse
import json
from pathlib import Path
import re
import struct


def _string(data,offset):
    if not 0<=offset<len(data):raise ValueError('String offset outside section')
    end=data.find(b'\0',offset)
    if end<0:raise ValueError('Unterminated ELF string')
    return data[offset:end].decode('ascii')


def compact_imports(data):
    if not data:raise ValueError('Empty compact version section')
    result={};offset=0
    while offset<len(data):
        if len(data)-offset<9:raise ValueError('Truncated compact version record')
        next_offset,crc=struct.unpack_from('<II',data,offset)
        if not next_offset:
            if crc==0 and not any(data[offset+8:]):return result
            raise ValueError('Invalid compact version terminator')
        end=offset+next_offset if next_offset else len(data)
        if end>len(data) or end<=offset+8 or (next_offset and next_offset%4):
            raise ValueError('Invalid compact version next offset')
        name=_string(data[offset+8:end],0)
        if not re.fullmatch(r'[A-Za-z0-9_.$]+',name) or name in result:
            raise ValueError('Invalid or duplicate imported symbol')
        padding=data[offset+8+len(name)+1:end]
        if any(padding):raise ValueError('Unexpected version record padding')
        result[name]=crc
        offset=end
    if data:raise ValueError('Missing compact version terminator')
    return result


class ModuleELF:
    def __init__(self,data):
        self.raw=data
        if len(data)<64:raise ValueError('Truncated ELF header')
        h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
        if h[0][:7]!=b'\x7fELF\x02\x01\x01' or h[1]!=1 or h[2]!=183:
            raise ValueError('Expected AArch64 ELF64 LE relocatable module')
        if h[11]!=64 or not h[12] or h[13]>=h[12]:raise ValueError('Unsupported section table')
        if h[6]+h[11]*h[12]>len(data):raise ValueError('Truncated section table')
        self.sections=[struct.unpack_from('<IIQQQQIIQQ',data,h[6]+64*i) for i in range(h[12])]
        names=self.section_data(h[13]);self.by_name={}
        for index,s in enumerate(self.sections):
            name=_string(names,s[0])
            if name in self.by_name:
                if name in ['__versions','__ksymtab','__ksymtab_gpl','__kcrctab','__kcrctab_gpl','.symtab']:
                    raise ValueError('Duplicate metadata section name')
                continue
            self.by_name[name]=index

    def section_data(self,index):
        if not 0<=index<len(self.sections):raise ValueError('Invalid section index')
        s=self.sections[index]
        if s[1]==8 or s[4]+s[5]>len(self.raw):raise ValueError('Unsupported or truncated section')
        return self.raw[s[4]:s[4]+s[5]]

    def imports(self):
        if '__versions' not in self.by_name:raise ValueError('Missing version section')
        return compact_imports(self.section_data(self.by_name['__versions']))

    def exports(self):
        result={}
        for suffix in ['','_gpl']:
            name='__ksymtab'+suffix
            if name not in self.by_name:continue
            index=self.by_name[name];symbols=self.section_data(index)
            if len(symbols)%12:raise ValueError('Unsupported kernel_symbol layout')
            count=len(symbols)//12
            crc_index=self.by_name.get('__kcrctab'+suffix)
            if crc_index is None:raise ValueError('Missing export CRC table')
            crc_data=self.section_data(crc_index)
            if len(crc_data)!=count*4:raise ValueError('Invalid export CRC count')
            if any(s[1] in [4,9] and s[7]==crc_index for s in self.sections):
                raise ValueError('Relative CRC table not supported')
            relocations=[i for i,s in enumerate(self.sections) if s[1]==4 and s[7]==index]
            if len(relocations)!=1:raise ValueError('Missing or duplicate export relocation table')
            relocation=self.sections[relocations[0]];symtab_index=relocation[6]
            if not 0<=symtab_index<len(self.sections):raise ValueError('Invalid symbol table index')
            symtab=self.sections[symtab_index];symbytes=self.section_data(symtab_index)
            if symtab[1]!=2 or symtab[9]!=24 or len(symbytes)%24:raise ValueError('Invalid symbol table')
            names={};relbytes=self.section_data(relocations[0])
            if relocation[9]!=24 or len(relbytes)%24:raise ValueError('Invalid relocation table')
            for off in range(0,len(relbytes),24):
                location,info,addend=struct.unpack_from('<QQq',relbytes,off)
                if location%12!=4:continue
                if location>=len(symbols) or info&0xffffffff!=261:raise ValueError('Invalid PREL32 name relocation')
                symbol_index=info>>32
                if symbol_index*24>=len(symbytes):raise ValueError('Invalid relocation symbol index')
                s=struct.unpack_from('<IBBHQQ',symbytes,symbol_index*24)
                exported=_string(self.section_data(s[3]),s[4]+addend)
                position=location//12
                if position in names:raise ValueError('Duplicate name relocation')
                if not re.fullmatch(r'[A-Za-z0-9_.$]+',exported):raise ValueError('Invalid export name')
                names[position]=exported
            if set(names)!=set(range(count)):raise ValueError('Incomplete export name mapping')
            for position,exported in names.items():
                if exported in result:raise ValueError('Duplicate exported symbol')
                result[exported]=struct.unpack_from('<I',crc_data,position*4)[0]
        return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module',type=Path,required=True)
    args=parser.parse_args()
    try:
        module=ModuleELF(args.module.read_bytes())
        result={'imports':module.imports(),'exports':module.exports()}
    except (OSError,ValueError,UnicodeError,struct.error) as exc:parser.error(str(exc))
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
