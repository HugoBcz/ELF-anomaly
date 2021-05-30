import json

class FileLoader:


    def __init__(self, path):
        self.path = path
        
        with open(self.path,"rb") as f:
            self.binary = f.read().hex()
        
    
    def writeBinary(self):
        with open("binary.txt","w") as f:
            f.write(self.binary)
            f.close()
    
    def headerInfo(self):
        f= open("Json_file/header.json")
        data = json.load(f)
        
        magic = self.binary[0:8]
        if magic != data["header"]["magic"]:
            print("Magic header doesn't correspond",magic,data["header"]["magic"])
        else : print("ok")
        try:
            byteFormat = data["header"]["class"][self.binary[8:10]]
            print(byteFormat)
        except:
            print("The format is not correct")
        try:
            machine = data["header"]["machine"][self.binary[36:38]]
            print(machine)
        except:
            print("This machine is not referenced")