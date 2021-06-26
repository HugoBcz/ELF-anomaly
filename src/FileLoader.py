import json
import sys
from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NullSection, StringTableSection, SymbolTableSection
from elftools.elf.segments import InterpSegment

from func import compute_entropy
from func import get_section_name
from func import get_segment_name
from func import overlap_address

class FileLoader:


    def __init__(self, path):
        self.path = path
        
        f = open(self.path,"rb")
        self.stream = f
        self.binary = f.read()
        self.file = ELFFile(f)

        header = self.file.header

        ### Header infos
        self.elfclass = header["e_ident"]["EI_CLASS"]
        self.data = header["e_ident"]["EI_DATA"]
        self.version = header["e_ident"]["EI_VERSION"]
        self.osabi = header["e_ident"]["EI_OSABI"]
        self.abiversion = str(header["e_ident"]["EI_ABIVERSION"])
        self.type = header["e_type"]
        self.machine = header["e_machine"]
        self.machine_version = header["e_version"]
        self.e_entry = header["e_entry"]
        self.e_phoff = header["e_phoff"]
        self.e_shoff = header["e_shoff"]
        self.e_flags = header["e_flags"]
        self.e_ehsize = header["e_ehsize"]
        self.e_phentsize = header["e_phentsize"]
        self.e_phnum = header["e_phnum"]
        self.e_shentsize = header["e_shentsize"]
        self.e_shnum = header["e_shnum"]
        self.e_shstrndx = header["e_shstrndx"]

        
    ### Write the file in hex format in binary.txt file
    def writeBinary(self):
        with open("binary.txt","w") as f:
            f.write(self.binary.hex())
            f.close()

    ### Check for unusual entropy
    def entropy(self,threshold):
        s = {}
        for section in self.file.iter_sections():
            size = section.header['sh_size']
            if size != 0:
                data = section.data()
                entropy, frequence = compute_entropy(data)
                if entropy > threshold:

                    stringTable = self.file.get_section(self.e_shstrndx)
                    offset = section.header['sh_name']
                    if isinstance(stringTable,StringTableSection):
                        name = stringTable.get_string(offset)
                        s[name]=entropy
                    else:
                        s[section.header['sh_name']]
        if s == []:
            print("General entropy is normal")
        else:
            print("Some section have unusual high entropy : {}".format(s))


    ### Check for potential overlapping segments
    def overlappingSegments(self):
        segments = []
        overlap = False
        for segment in self.file.iter_segments():
            header = segment.header
            addr = header["p_vaddr"]
            size = header['p_memsz']
            if segments!=[]:
                for seg in segments:
                    addr1,addr2 = hex(addr),hex(addr+size)
                    addr3,addr4,p_type = seg
                    if overlap_address(addr1,addr2,addr3,addr4):
                        print("Overlapping detected between two segments: Range [{}-{}],{} overlap range [{}-{}],{}".format(addr1,addr2,header['p_type'],addr3,addr4,p_type))
                        overlap = True
            segments.append((hex(addr),hex(addr+size),header['p_type']))
        if not overlap:
            print("No overlap detected between segments")
        
    
    ### Check for potential overlapping sections
    def overlappingSections(self):
        sections = []
        overlap = False
        for section in self.file.iter_sections():
            header = section.header
            addr = header["sh_addr"]
            size = header['sh_size']
            stringTable = self.file.get_section(self.e_shstrndx)
            if isinstance(stringTable,StringTableSection):
                name = stringTable.get_string(header['sh_name'])
            else:
                name = header['sh_name']
            addr1,addr2 = '0x'+'0'*(9-len(hex(addr)))+hex(addr)[2:],'0x'+'0'*(9-len(hex(addr+size)))+hex(addr+size)[2:]
            if sections!=[]:
                for seg in sections:
                    addr3,addr4,sh_name = seg
                    if overlap_address(addr1,addr2,addr3,addr4):
                        print("Overlapping detected between two sections: Range [{}-{}],{} overlap range [{}-{}],{}".format(addr1,addr2,name,addr3,addr4,sh_name))
                        overlap = True
            sections.append((addr1,addr2,name))
        if not overlap:
            print("No overlap detected between sections")

    ### Check for unusual segments permissions
    def segmentPermissions(self):
        problem = False
        for segment in self.file.iter_segments():
            header = segment.header

            if header['p_type'] == 'PT_LOAD':
                text = self.file.get_section_by_name('.text')
                data = self.file.get_section_by_name('.data')
                bss = self.file.get_section_by_name('.bss')
                
                
                flag = bin(header['p_flags'])[2:]
                permission = ["READ","WRITE","EXECUTE"]
                for index in range(3):
                    if flag[index] == '0':
                        permission.pop(index)
                
                
                if segment.section_in_segment(text):
                    if header['p_flags']!=5:
                        print("Typical text segments have read and execute, but not write permissions : Found {}".format(permission))
                        problem = True

                if segment.section_in_segment(data) and segment.section_in_segment(bss):
                    if header['p_flags']!=7:
                        print("Data segments normally have read, write, and execute permissions : Found {}".format(permission))
                        problem = True
        
        if not problem:
            print("All the permissions are normally set")
    
    #### Chech for unusual sections permissions
    def sectionPermissions(self):
        
        problem = False

        try:
            text = self.file.get_section_by_name('.text')
            flag = text.header['sh_flags']
            permission = ["SHF_EXECINSTR","SHF_ALLOC","SHF_WRITE"]
            f = bin(flag)[-3:]
            for index in range(3):
                    if f[index] == '0':
                        permission.pop(index)
            if flag != 6:
                print("Permission for .text section should be SHF_ALLOC,SHF_EXECINSTR but {} have been found".format(permission))
                problem = True

        except :
            print("There is no .text sections")
        
        try:
            data = self.file.get_section_by_name('.data')
            flag = data.header['sh_flags']
            permission = ["SHF_EXECINSTR","SHF_ALLOC","SHF_WRITE"]
            f = bin(flag)[-3:]
            for index in range(3):
                    if f[index] == '0':
                        permission.pop(index)
            if flag != 3:
                print("Permission for .data section should be SHF_ALLOC,SHF_WRITE but {} have been found".format(permission))
                problem = True
        except :
            print("There is no .data sections")

        try:
            data = self.file.get_section_by_name('.bss')
            flag = data.header['sh_flags']
            permission = ["SHF_EXECINSTR","SHF_ALLOC","SHF_WRITE"]
            f = bin(flag)[-3:]
            for index in range(3):
                    if f[index] == '0':
                        permission.pop(index)
            if flag != 3:
                print("Permission for .bss section should be SHF_ALLOC,SHF_WRITE but {} have been found".format(permission))
                problem = True
        except :
            print("There is no .bss sections")
        
        try:
            data = self.file.get_section_by_name('.rodata')
            flag = data.header['sh_flags']
            permission = ["SHF_EXECINSTR","SHF_ALLOC","SHF_WRITE"]
            f = bin(flag)[-3:]
            for index in range(3):
                    if f[index] == '0':
                        permission.pop(index)
            if flag != 2:
                print("Permission for .rodata section should be SHF_ALLOC but {} have been found".format(permission))
                problem = True
        except :
            print("There is no .rodata sections")
        
        try:
            data = self.file.get_section_by_name('.init')
            flag = data.header['sh_flags']
            permission = ["SHF_EXECINSTR","SHF_ALLOC","SHF_WRITE"]
            f = bin(flag)[-3:]
            for index in range(3):
                    if f[index] == '0':
                        permission.pop(index)
            if flag != 6:
                print("Permission for .init section should be SHF_ALLOC, SHF_EXECINSTR but {} have been found".format(permission))
                problem = True
        except :
            print("There is no .init sections")
        
        try:
            data = self.file.get_section_by_name('.fini')
            flag = data.header['sh_flags']
            permission = ["SHF_EXECINSTR","SHF_ALLOC","SHF_WRITE"]
            f = bin(flag)[-3:]
            for index in range(3):
                    if f[index] == '0':
                        permission.pop(index)
            if flag != 6:
                print("Permission for .fini section should be SHF_ALLOC, SHF_EXECINSTR but {} have been found".format(permission))
                problem = True
        except :
            print("There is no .fini sections")
        
        try:
            data = self.file.get_section_by_name('.dynstr')
            flag = data.header['sh_flags']
            permission = ["SHF_EXECINSTR","SHF_ALLOC","SHF_WRITE"]
            f = bin(flag)[-3:]
            for index in range(3):
                    if f[index] == '0':
                        permission.pop(index)
            if flag != 2:
                print("Permission for .dynstr section should be SHF_ALLOC but {} have been found".format(permission))
                problem = True
        except :
            print("There is no .dynstr sections")
        
        try:
            data = self.file.get_section_by_name('.dynsym')
            flag = data.header['sh_flags']
            permission = ["SHF_EXECINSTR","SHF_ALLOC","SHF_WRITE"]
            f = bin(flag)[-3:]
            for index in range(3):
                    if f[index] == '0':
                        permission.pop(index)
            if flag != 2:
                print("Permission for .dynsym section should be SHF_ALLOC but {} have been found".format(permission))
                problem = True
        except :
            print("There is no .dynsym sections")
        
        try:
            data = self.file.get_section_by_name('.init_array')
            flag = data.header['sh_flags']
            permission = ["SHF_EXECINSTR","SHF_ALLOC","SHF_WRITE"]
            f = bin(flag)[-3:]
            for index in range(3):
                    if f[index] == '0':
                        permission.pop(index)
            if flag != 3:
                print("Permission for .init_array section should be SHF_ALLOC,SHF_WRITE but {} have been found".format(permission))
                problem = True
        except :
            print("There is no .init_array sections")
        
        try:
            data = self.file.get_section_by_name('.fini_array')
            flag = data.header['sh_flags']
            permission = ["SHF_EXECINSTR","SHF_ALLOC","SHF_WRITE"]
            f = bin(flag)[-3:]
            for index in range(3):
                    if f[index] == '0':
                        permission.pop(index)
            if flag != 3:
                print("Permission for .fini_array section should be SHF_ALLOC,SHF_WRITE but {} have been found".format(permission))
                problem = True
        except :
            print("There is no .fini_array sections")
        
        if not problem:
            print("No strange section permissions have been reported")
        
        

        
    ### Check the program interpreter
    def programInterpreter(self):
        for segment in self.file.iter_segments():
            header = segment.header
            if header['p_type'] == 'PT_INTERP':
                INTERP = InterpSegment(segment.header,self.stream)
                interpreter = INTERP.get_interp_name()
                if interpreter == None:
                    print("There is no interpreter for this ELF")
                else:
                    print("Interpreter found : {}".format(interpreter))
    

    ### Check the number of section and segment
    def sNumber(self):
        load=0
        for segment in self.file.iter_segments():
            if segment.header['p_type'] == 'PT_LOAD':
                load+=1
        if self.e_phnum == 0 or self.e_shnum == 0:
            print("Unusual number of segment or sections : {} segment(s) and {} section(s) ({} PT_LOAD segment(s))".format(self.e_phnum,self.e_shnum,load))
        else:
            print("There is {} segment(s) and {} section(s) ({} PT_LOAD segment(s))".format(self.e_phnum,self.e_shnum,load))


    ### Check the entry point
    def entryPoint(self):

        (sh_name, sh_type) = get_section_name(self.file,hex(self.e_entry),self.e_shstrndx)
        p_type = get_segment_name(self.file,hex(self.e_entry))
        print("Entry point to section {} in segment {}".format(sh_name,p_type))



    ### Check the symbol table
    def symbolTable(self):
        sym = False
        symbol = []
        for section in self.file.iter_sections():
            if isinstance(section,SymbolTableSection):
                sym = True
                for s in section.iter_symbols():
                    symbol.append(s.name)
                print("Instance of symbol table found : {}".format(symbol))
        if not sym:
            print("There is no instance of symbol table")

    ### Check the string table index
    def stringTable(self):
        stringTable = self.file.get_section(self.e_shstrndx)
        if isinstance(stringTable,StringTableSection):
            print("The string table index is correct")
        else:
            print("The string table index is wrong")

    def test(self):
        pass