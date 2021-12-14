from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

PADD_CHAR = '\\'.encode('utf-8')
BLOCK_SIZE = 16



class AESCipher:
    """
    AES256 cipher in CBC mode. Encrypt and decrypt by the couple (key/iv) with 256 bits keys
    """
    
    def __init__(self):
        # Padded store
        self.padded = 0
        # Generate key hash
        self.key = self.gen_key()
        # Generate 16 random bytes for IV
        self.iv = self.gen_iv()
        # Save key in Cipher object
        print('[+] Generate key', (self.key))
         

    def ask_password(self):
        """
        Function to ask password
        """
        password = input('[*] Enter password: ')
        password = password.encode('utf-8')
        return password

    def gen_key(self):
        """
        Generate hashkey in 256 bits
        """
        return hashlib.sha256().digest()

    def gen_iv(self):
        """
        Generate IV for first block in CBC mode
        """
        return get_random_bytes(BLOCK_SIZE)

    def padding(self, password):
        """
        Add padding when it's necessary for AES block before encryptio
        Length of password must a multiple of 16 (block of 16 bytes) for cipher
        """
        print('[*] Length before padding: ',str(len(password)))
        padd_added = 0
        if type(password) != bytes :
            password = password.encode('utf-8')
        while len(password) % BLOCK_SIZE != 0 :
            password += PADD_CHAR
            padd_added += 1
        print('[+] Password after padding: ', password) 
        print('[+] Length after padding: ',str(len(password)))
        return password

    def unpadding(self, password):
        """
        Unpadding the characters added by padding function after decryption
        """
        password = password.decode('utf-8')
        while password[-1] == PADD_CHAR.decode('utf-8'):
            password = password[:-1]
        return password



    def encrypt(self, plaintext):
        """
        Encrypt plaintext to ciphertext
        """
        plaintext = self.padding(plaintext)
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        cipher_text = self.cipher.encrypt(plaintext)
        print('[+] Encryption plain text :', cipher_text)
        return cipher_text


    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext to plaintext
        """
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        plaintext = self.cipher.decrypt(ciphertext)
        plaintext = self.unpadding(plaintext)
        print('[+] Decryption cipher text :', plaintext)
        return plaintext

    

