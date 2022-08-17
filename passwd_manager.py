import json
class Passwd_manager():
    def __init__(self,json_file,passwd_file):
        self.json_file = json_file
        self.passwd_file = passwd_file
        self.en_list = []
        self.den_list = []
        self.verified = False
        self.en_passwd = None
        self.den_passwd = None
        self.is_dencrypted = False
    def read_json(self):
        try:
            with open(self.json_file,'r') as f:
                self.en_list = json.load(f)
        except FileNotFoundError:
            with open(self.json_file,'w') as f:
                json.dump([],f)
            self.en_list = []
        return self.en_list

    def update_json(self,new_list):
        self.en_list.insert(0,new_list)
    def find_file_passwd(self,file_name):
        for i in self.den_list:
            if i[0] == file_name:
                passwd = i[1]
                return passwd
        return None

    def remove_key(self,file):
        for i in self.en_list:
            if i[0] == file:
                self.en_list.remove(i)
                break
        for r in self.den_list:
            if r[0] == file:
                self.den_list.remove(r)
                break
    def write_json(self):
        with open(self.json_file,'w') as f:
            json.dump(self.en_list,f)

    def read_en_passwd(self):
        try:
            with open(self.passwd_file,'rb') as f:
                self.en_passwd = f.read()
        except FileNotFoundError:
            with open(self.passwd_file,'wb+') as f:
                self.en_passwd = f.read()
        
    def write_en_passwd(self):
        with open(self.passwd_file,'wb') as f:
            f.write(self.en_passwd)
def key_padding(key):
        rest = len(key) % 16
        if rest != 0:
            for i in range(0,16 - rest):
                key += b'\x00'
        return key
def check_key(key):
    if key != None: 
        if key.isspace() == False and 8<= len(key) <= 16 :
            return True
        else:
            return False
    else:
        return None