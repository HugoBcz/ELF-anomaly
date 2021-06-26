# ELF-anomaly

This project is about detecting anomaly in ELF file, all the scripts are python3 based, you may need to install some packages before trying to start the program. All the dependencies are listed below. 

### Dependencies
**pip install pyelftools**

## Start the program

All the python scripts are located in the **/src** folder :
* **main.py** : Contain the main function to execute the program
* **FileLoader.py** : Contain all the main functionalities of the project
* **func.py** : Contain useful side function

To start the analysis, you first should have the path of your ELF file. The command to run the analysis is :

```python
python3 main.py your_elffile_path --options
```

### Options

List of available options for your analysis :

```python
[-w],[--write], Write the binary in a txt file
[-t], type=int, default=6, Change the default threshold for the entropy
```

## Functionalities 

List of available functionalities :

### Entropy Computation

```python
def entropy(self,threshold):
```
Compute the entropy of each sections and raise an alert when it overcomes the threshold (-t option). The default threshold is fixed to 6. If every sections have low entropy, it prints "General entropy is normal".

### Number of segment and sections

```python
def sNumber(self):
```

Check the number of sections and segments in the ELF file and print it with the number of PT_LOAD segment.

### Potential overlapping segments

```python
def overlappingSegments(self):
```

It checks for potential overlapping segments, when an overlap is detected, it prints the two segments that overlap together and their range. It's quite frequent that segment overlap, but the user must be careful when two PT_LOAD or PT_DYNAMIC segments overlap.

Be careful, sometimes false overlap can be detected due to the address format.

### Potential overlapping segments

```python
def overlappingSections(self):
```

It checks for potential overlapping sections, when an overlap is detected, it prints the two sections that overlap together and their range. .Comment section and .String_table can overlap but it's not a problem.

Be careful, sometimes false overlap can be detected due to the address format.

### Segment permissions

```python
def segmentPermissions(self):
```

Check the permissions on the segments containing the .text section, the .data section and the .bss section. 

### Section permissions

```python
def sectionPermissions(self):
```

Check the permissions on standard primary sections according their expected use. It checks the permission on .text, .data, .bss, .rodata, .init, .fini, .dynstr, .dynsym, .init_array, .fini_array. If the program doesn't find the section in the ELF file, it prints : "There is no .fini_array sections". If there is no strange permissions, it prints : "No strange section permissions have been reported" 

### Interpreter

```python
def programInterpreter(self):
```

Indicate weither an interpreter has been found and if it's the case, print the name of the interpreter. 

### Symbol table

```python
def symbolTable(self):
```

Iter on all the sections in the ELF file to check if there is any instance of symbol table and then print all the symbol, if there is no symbol table, it prints "There is no instance of symbol table".

### String table index

```python
def stringTable(self):
```

Check if the string table index given in the header table correspond to the string table, if not raise an alert.

### Entry point

