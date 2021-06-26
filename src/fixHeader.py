import lief
from func import compute_entry_point

def changeEntryPoint(file, entry_point):
        e_shstrndx = file.header["e_shstrndx"]
        compute_entry_point(file, entry_point,e_shstrndx)
        #binary = lief.parse(self.path)
        #header = binary.header
        #header.entrypoint = entry_point
        #binary.write("output/sample")
