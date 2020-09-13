#YAHIKO-SIX-PATHS
import hashlib ,os, datetime, time,random #import lib
from datetime import date

try:
        while True:
                #encryptresult = open('encrypt-hash.txt', 'r+') -- can also write and put code here
                hash = (input('''|-------------<<<<<[]>>>>>-------------|
|    [   sha1    ]       [  blake2s  ] |
|    [   sha224  ]       [ shake_128 ] |
|    [  sha384   ]       [ shake_256 ] |
|    [   sha256  ]       [ sha3_224  ] |
|    [  sha512   ]       [ sha3_256  ] |
|    [    md5    ]       [ sha3_512  ] |
|    [  blake2b  ]                     |
|-------------<<<<<[]>>>>>-------------|
select hash: '''))
                if hash == 'sha1':
                        sha1_encrypt = (input("sha1 encrypt = ")) #input string
                        sha1result = hashlib.sha1(sha1_encrypt.encode('utf-8')).hexdigest()
                        print ("[", sha1result, "]")
                elif hash == 'sha224':
                        sha224_encrypt = (input("sha224 encrypt = ")) #input string
                        sha224result = hashlib.sha224(sha224_encrypt.encode('utf-8')).hexdigest() #output sha224 encrypt
                        print ("[", sha224result, "]")
                elif hash == 'sha384':
                        sha384_encrypt = (input("sha384_encrypt = "))
                        print ("[",hashlib.sha384(sha384_encrypt.encode('utf-8')).hexdigest(),"]")
                elif hash == 'sha256':
                        sha256_encrypt = (input("sha256 encrypt = "))
                        print ("[",hashlib.sha256(sha256_encrypt.encode('utf-8')).hexdigest(),"]")
                elif hash == 'sha512':
                        sha512_encrypt = (input("sha512 encrypt = "))
                        print ("[",hashlib.sha512(sha512_encrypt.encode('utf-8')).hexdigest(),"]")
                elif hash == 'md5':
                        md5_encrypt = (input("md5 encrypt = "))
                        print ("[",hashlib.md5(md5_encrypt.encode('utf-8')).hexdigest(),"]")
                elif hash == 'blake2b':
                        blake2b_encrypt = (input("blake2b encrypt = "))
                        print ("[",hashlib.blake2b(blake2b_encrypt.encode('utf-8')).hexdigest(),"]")
                elif hash == 'blake2s':
                        blake2s_encrypt = (input("blake2s encrypt = "))
                        print ("[",hashlib.blake2s(blake2s_encrypt.encode('utf-8')).hexdigest(),"]")
                elif hash == 'sha3_224':
                        sha3_224_encrypt = (input("sha3_224 encrypt = "))
                        print ("[",hashlib.sha3_224(sha3_224_encrypt.encode('utf-8')).hexdigest(),"]")
                elif hash == 'sha3_256':
                        sha3_256_encrypt = (input("sha3_256 encrypt = "))
                        print ("[",hashlib.sha3_256(sha3_256_encrypt.encode('utf-8')).hexdigest(),"]")
                elif hash == 'sha3_512':
                        sha3_512_encrypt = (input("sha3_512 encrypt = "))
                        print ("[",hashlib.sha3_512(sha3_512_encrypt.encode('utf-8')).hexdigest(),"]")
                else:
                        print("Nggak Ada Sayanggg")


                exit = input('''<<<<<<<<[]>>>>>>>>
[ 1.restart      ]
[ 2.save         ]
[ 3.exit         ]
[ 4.save & exit  ]
>\> ''')
                if exit == '1':
                        clear = lambda: os.system('clear')
                        clear()
                if exit == '2':
                        encryptresult = open('encrypt-hash.txt', 'a+')
                        encryptresult.write("[ " + str(sha1result) + " ]" + '\n')
                        encryptresult.close()
                        clear = lambda: os.system('clear')
                        clear()
                if exit == '3':
                        clear = lambda: os.system('clear')
                        clear()
                        break
                if exit == '4':
                        encryptresult = open('encrypt-hash.txt', 'a+')
                        encryptresult.write("[ " + str(sha1result) + " ]" + '\n')
                        encryptresult.close()
                        clear = lambda: os.system('clear')
                        clear()
                        break
                
except KeyboardInterrupt: #Keyboard Interrupt
                print("Makan ya Sayanggku")
finally:
        print("Sayangku Maniss")
