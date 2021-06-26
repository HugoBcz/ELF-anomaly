import sys
import argparse
from FileLoader import FileLoader

def print_dashline():
    print("-----------------------------------------")

def main():
    #Main function
    parser = argparse.ArgumentParser(description='Analyse the ELF file')
    parser.add_argument("path", help="path of the ELF file to analyse")
    parser.add_argument("-w", "--write", help="write the binary in a txt file", action="store_true")
    parser.add_argument("-e", "--entry_point", help="change entry point", action="store_true")
    parser.add_argument("-n", "--none", help="no print", action="store_true")
    parser.add_argument("-t", type=int, default=6, help=" Change the default threshold for the entropy")
    args = parser.parse_args()

    path = args.path
    f = FileLoader(path)

    threshold = args.t


    ### Analysis part ###

    if not args.none:

        print("Analysis begin for file : {}\n".format(path))

        #Computation of entropy
        print_dashline()
        print("Entropy Computation\n")
        f.entropy(threshold)

        #Check the number of segment and sections
        print_dashline()
        print("Number of segment and sections\n")
        f.sNumber()

        #Check for potential overlapping segments
        print_dashline()
        print("Potential overlapping segments\n")
        print("(Segments overlapping doesn't always anomaly, look carefully to the overlap between two PT_LOAD segments)\n")
        f.overlappingSegments()

        #Check for potential overlapping sections
        print_dashline()
        print("Potential overlapping sections\n")
        f.overlappingSections()

        #Check for unusual segment permissions
        print_dashline()
        print("Segment permissions\n")
        f.segmentPermissions()

        #Check for unusual section permissions
        print_dashline()
        print("Section permissions\n")
        f.sectionPermissions()

        #Check the program interpreter
        print_dashline()
        print("Interpreter\n")
        f.programInterpreter()

        #Check symbol table
        print_dashline()
        print("Symbol table\n")
        f.symbolTable()

        #Check string table index
        print_dashline()
        print("String table index\n")
        f.stringTable()

        #Check for weird entry point
        print_dashline()
        print("Entry point\n")
        print("(Entry_point point usually to PT_LOAD or PT_DYNAMIC segment and .text section)\n")
        f.entryPoint()

    

    if args.write:
        f.writeBinary()
    
    if args.entry_point:
        f.changeEPoint()


if __name__ == "__main__":
    main()