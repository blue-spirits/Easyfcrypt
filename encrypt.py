from Crypto.Cipher import AES




class Encrypt():
    def __init__(self, text, key):
        self.text = text
        self.key = key
        self.length = len(self.text)
        self.rest_num = self.length % 16

    def ECB(self):
        aes = AES.new(self.key, AES.MODE_ECB)
        self.text = aes.encrypt(self.text)

    def pkcs7(self):
        padding_num = 16 - self.rest_num
        for i in range(0, padding_num):
            self.text += padding_num.to_bytes(1, 'little')


class File_object():
    def __init__(self, file):
        self.file = file

    def read_bytes(self):
        try:
            with open(self.file, 'rb') as f:
                bytes = f.read()
                return bytes
        except FileNotFoundError:
            return None

    def write_bytes(self, bytes):
        with open(self.file, 'wb') as f:
            f.write(bytes)


class Dencrypt():
    def __init__(self, text, key):
        self.text = text
        self.key = key

    def ECB(self):
        aes = AES.new(self.key, AES.MODE_ECB)
        self.text = aes.decrypt(self.text)
    def pkcs7(self):
        padding_num = self.text[-1]
        if type(padding_num) == int and padding_num <= 16:
            end_list = self.text[0 - padding_num:]
            for i in end_list:
                if i != padding_num:
                    self.text = None
        else:
            self.text = None
        return self.text[0:0 - padding_num]