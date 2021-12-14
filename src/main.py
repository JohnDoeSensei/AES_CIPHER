from Cipher import AESCipher 

cipher = AESCipher()
password = cipher.ask_password()
cipherpassword = cipher.encrypt(password)
plainpassword = cipher.decrypt(cipherpassword)