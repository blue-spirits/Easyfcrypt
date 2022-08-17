from Crypto.Cipher import AES




class Encrypt():
    def __init__(self, text, key):
        self.text = text
        self.key = key
        self.length = len(self.text)
        self.rest_num = self.length % 16

    def ECB(self):
        aes = AES.new(self.key, AES.MODE_ECB)
        en_text = aes.encrypt(self.text)
        return en_text

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
    def __init__(self, en_text, key):
        self.en_text = en_text
        self.key = key
        self.den_text = b''

    def ECB(self):
        aes = AES.new(self.key, AES.MODE_ECB)
        self.den_text = aes.decrypt(self.en_text)
        return self.den_text
    def pkcs7(self):
        padding_num = self.den_text[-1]
        if type(padding_num) == int and padding_num <= 16:
            end_list = self.den_text[0 - padding_num:]
            for i in end_list:
                if i != padding_num:
                    self.den_text = None
                    return None
        else:
            return None
        self.den_text = self.den_text[0:0 - padding_num]
        return self.den_text