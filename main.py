import sys
import argparse
from FileLoader import FileLoader

def main():
    #Main function
    parser = argparse.ArgumentParser(description='Analyse the ELF file')
    parser.add_argument("path", help="path of the ELF file to analyse")
    parser.add_argument("-w", "--write", help="write the binary in a txt file", action="store_true")
    args = parser.parse_args()

    path = args.path
    f = FileLoader(path)
    f.headerInfo()
    print(f.binary[36:40])
    

    if args.write:
        f.writeBinary()

if __name__ == "__main__":
    main()