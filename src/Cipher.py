from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify as hexa


BLOCK_SIZE = 16

class AESCipher:
    def ask_password(self):
        password = input('[*] Enter password: ')
        print('Lenght\'s password: '+str(password))
        self.ask_password = password

    def __init__(self, type, size):
        """
        AES supports multiple key sizes: 16 (AES128), 24 (AES192), or 32 (AES256).
        """
        if type == 'AES':
            self.type = 'AES_CIPHER'
        # Generate string random bytes
        if size == 16 or size == 24 or size == 32: 
            self.key = get_random_bytes(size)
        self.iv = get_random_bytes(AES.block_size)
        # Save key in Cipher object
        print('[+] Generate key', hexa(self.key).decode('utf-8'))
        # Create unique cipher
         

    def encrypt(self, plaintext):
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        plaintext = bytes(plaintext,'utf-8')
        plaintext_padded = pad(plaintext, BLOCK_SIZE)
        cipher_text = self.cipher.encrypt(plaintext_padded)
        print('cipher text hex:',  hexa(cipher_text).decode())
        print('cipher text bytes:', cipher_text)
        return cipher_text

    def decrypt(self, ciphertext):
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext_unpadded = unpad(ciphertext, BLOCK_SIZE)
        print(ciphertext_unpadded)
        plaintext = self.cipher.decrypt(ciphertext_unpadded)
        return hexa(plaintext).decode()


c = AESCipher('AES',16)