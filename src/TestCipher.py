from Cipher import AESCipher

nb_test = 4
score = 0


def init_cipher(type='AES', size=32):
    return True, AESCipher(type, size)

def test_decrypt(self, c, message ):
    pass



def test_encrypt( c , message): 
    ciphertext = c.encrypt(message)
    plaintext = c.decrypt(ciphertext)
    
    
    


def get_score(result, score, nb_test):
    if result :
        score +=1 
        print('[!] Test passed')
        print('[+] Score: '+str(score)+'/'+str(nb_test))
    else :
        print('[!] Test not passed')
        print('[-] Score: '+str(score)+'/'+str(nb_test))

    

def main_test(type, size, score, nb_test):
    result = init_cipher(type, size)
    get_score(result[0], score, nb_test)
    cipher = result[1]
    test_encrypt(cipher, '12345kqosfù)$/;s@{é&g')



main_test('AES', 32, score, nb_test)

    