from Cipher import AESCipher

nb_test = 2
score = 0


def init_cipher():
    return True, AESCipher()


def test_cipher( c , message): 
    ciphertext = c.encrypt(message)
    plaintext = c.decrypt(ciphertext)
    if plaintext == message :
        return True
    return False
    

def get_score(result, score, nb_test):
    if result :
        score +=1 
        print('[!] Test passed')
        print('[+] Score: '+str(score)+'/'+str(nb_test))
    else :
        print('[!] Test not passed')
        print('[-] Score: '+str(score)+'/'+str(nb_test))

    return score

def main_test(score, nb_test):
    result = init_cipher()
    score = get_score(result[0], score, nb_test)
    cipher = result[1]
    result2 = test_cipher(cipher, '12345kqosfù)$/;s@{é&g')
    score = get_score(result2, score, nb_test)



main_test(score, nb_test)

    