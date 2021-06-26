# ELF-anomaly

This project is about detecting anomaly in ELF file, all the scripts are python based, you may need to install some packages before trying to start the program. All the dependencies are listed below. 

### Dependencies
**pip install pyelftools**

## Start the program

All the python scripts are located in the **/src** folder :
* main.py : Contain the main function to execute the program
* FileLoader.py : Contain all the main functionalities of the project
* func.py : Contain useful side function

To start the analysis, you first should have the path of your ELF file. The command to run the analysis is :

```bash
python3 main.py your_elffile_path --options
```

### Options

List of available options for your analysis :

*[-w],[--write], Write the binary in a txt file
*[-t], type=int, default=6, Change the default threshold for the entropy

## Functionalities 

List of available functionalities :

### Entropy Computation

### Number of segment and sections

### Potential overlapping segments

### Segment permissions

### Section permissions

### Interpreter

### Symbol table

### Entry point

