import sys 
import math
from math import log
import numpy as np
import matplotlib.pyplot as plt
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NullSection, StringTableSection, SymbolTableSection


def get_section_name(file,address,e_shstrndx):
    for sections in file.iter_sections():
        header = sections.header
        addr = header['sh_addr']
        size = header['sh_size']
        if (hex(addr) <= address) and (address < hex(addr + size)):
            stringTable = file.get_section(e_shstrndx)
            if isinstance(stringTable,StringTableSection):
                name = header['sh_name']
                return stringTable.get_string(name), header['sh_type']
            else:
                return header['sh_name'], header['sh_type']
    

def get_segment_name(file,address):
    for segment in file.iter_segments():
        header = segment.header
        addr = header["p_vaddr"]
        size = header['p_memsz']
        if (hex(addr) <= address) and (address < hex(addr + size)):
            return header['p_type']

def overlap_address(addr1,addr2,addr3,addr4):
    return (addr1 <= addr3 and addr3 < addr2) or (addr3 <= addr1 and addr1 < addr4)



def compute_entropy(binary):
    
    byteArr = list(binary)
    fileSize = len(byteArr) 

    #Calculate the frequency for each byte
    freq = [] 
    for i in range(256): 
        counter = 0 
        for byte in byteArr: 
            if byte == i: 
                counter += 1 
        freq.append(float(counter) / fileSize) 

    #Compute Shannon entropy
    ent = 0.0 
    for f in freq: 
        if f > 0: 
            ent = ent + f * log(f, 2) 
    ent = -ent
   
    return ent, freq

