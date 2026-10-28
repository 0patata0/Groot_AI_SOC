import importlib.util
from pathlib import Path
import struct
import unittest

PATH=Path(__file__).resolve().parents[1]/'driver-diagnostics/elf_versions.py'
SPEC=importlib.util.spec_from_file_location('driver_elf_versions',PATH)
ELF=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(ELF)


def versions(records):
    out=b''
    for name,crc in records:
        raw=name.encode()+b'\0';size=(8+len(raw)+3)//4*4
        out+=struct.pack('<II',size,crc)+raw+b'\0'*(size-8-len(raw))
    return out+b'\0'*9


def module_bytes(*,bad_relocation=False,duplicate_metadata=False):
    # Two exported names use distinct CRCs, name offsets, and relocation indices.
    symbols=b'export_a\0export_b\0'
    symtab=b'\0'*24+struct.pack('<IBBHQQ',0,0,0,3,0,0)+struct.pack('<IBBHQQ',0,0,0,3,9,0)
    reloc=b''.join(struct.pack('<QQq',off,(index<<32)|(260 if bad_relocation else 261),0)
                   for off,index in [(4,1),(16,2)])
    sections=[('',0,b'',0,0,0),('.shstrtab',3,b'',0,0,0),
              ('__versions',1,versions([('needed_a',0x12345678),('needed_b',0x87654321)]),0,0,0),
              ('__ksymtab_strings',1,symbols,0,0,0),('.symtab',2,symtab,5,0,24),
              ('.strtab',3,b'\0',0,0,0),('__ksymtab',1,b'\0'*24,0,0,0),
              ('__kcrctab',1,struct.pack('<II',0x11223344,0xaabbccdd),0,0,0),
              ('.rela__ksymtab',4,reloc,4,6,24)]
    if duplicate_metadata:sections.append(('__versions',1,b'\0'*9,0,0,0))
    # Repeated irrelevant debug sections are valid ELF and must be ignored.
    sections += [('.debug_info',1,b'first',0,0,0),('.debug_info',1,b'second',0,0,0)]
    names=b'\0';name_offsets=[]
    for name,*_ in sections:
        name_offsets.append(len(names) if name else 0)
        if name:names+=name.encode()+b'\0'
    sections[1]=('.shstrtab',3,names,0,0,0)
    data=b'\0'*64;headers=[]
    for index,(_,kind,raw,link,info,entsize) in enumerate(sections):
        data+=b'\0'*((-len(data))%8);offset=len(data);data+=raw
        headers.append((name_offsets[index],kind,0,0,offset,len(raw),link,info,1,entsize))
    data+=b'\0'*((-len(data))%8);shoff=len(data)
    data+=b''.join(struct.pack('<IIQQQQIIQQ',*h) for h in headers)
    ident=b'\x7fELF\x02\x01\x01'+b'\0'*9
    header=struct.pack('<16sHHIQQQIHHHHHH',ident,1,183,1,0,0,shoff,0,64,0,0,64,len(headers),1)
    return header+data[64:]


class DriverELFTests(unittest.TestCase):
    def test_actual_compact_terminator_and_variable_lengths(self):
        data=versions([('a',1),('much_longer_symbol',0x87654321)])
        self.assertEqual(ELF.compact_imports(data),{'a':1,'much_longer_symbol':0x87654321})

    def test_reject_bad_next_padding_duplicates_and_termination(self):
        good=versions([('a',1)])
        cases=[b'',good[:-4],good[:-9],struct.pack('<II',3,1)+b'a\0',
               struct.pack('<II',1000,1)+b'a\0',versions([('a',1),('a',2)]),
               good[:-9]+struct.pack('<II',0,1)+b'\0']
        dirty=bytearray(good);dirty[10]=1;cases.append(bytes(dirty))
        for data in cases:
            with self.subTest(data=data),self.assertRaises(ValueError):ELF.compact_imports(data)

    def test_exports_resolve_prel32_names_to_absolute_crc(self):
        module=ELF.ModuleELF(module_bytes())
        self.assertEqual(module.imports(),{'needed_a':0x12345678,'needed_b':0x87654321})
        self.assertEqual(module.exports(),{'export_a':0x11223344,'export_b':0xaabbccdd})

    def test_wrong_relocation_and_duplicate_metadata_are_rejected(self):
        with self.assertRaisesRegex(ValueError,'PREL32'):ELF.ModuleELF(module_bytes(bad_relocation=True)).exports()
        with self.assertRaisesRegex(ValueError,'Duplicate metadata'):ELF.ModuleELF(module_bytes(duplicate_metadata=True))

    def test_truncated_or_wrong_architecture_is_rejected(self):
        for data in [b'',module_bytes()[:63],module_bytes()[:-1]]:
            with self.assertRaises(ValueError):ELF.ModuleELF(data)
        raw=bytearray(module_bytes());struct.pack_into('<H',raw,18,62)
        with self.assertRaisesRegex(ValueError,'AArch64'):ELF.ModuleELF(raw)


if __name__=='__main__':unittest.main()
