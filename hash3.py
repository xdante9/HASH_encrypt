#YAHIKO-SIX-PATHS
import hashlib ,os, datetime, time,random #import lib
from datetime import date

try:
        while True:
                #encryptresult = open('encrypt-hash.txt', 'r+') -- can also write and put code here
                hash = (input('''|-------------<<<<<[]>>>>>-------------|
|    [   sha1    ]       [  blake2s  ] |
|    [   sha224  ]       [ shake_128 ] |
|    [  sha256   ]       [ shake_256 ] |
|    [   sha384  ]       [ sha3_224  ] |
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
                elif hash == 'sha256':
                        sha256_encrypt = (input("sha256_encrypt = "))
                        sha256result = hashlib.sha256(sha256_encrypt.encode('utf-8')).hexdigest()
                        print ("[", sha256result, "]")
                elif hash == 'sha384':
                        sha384_encrypt = (input("sha384 encrypt = "))
                        sha384result = hashlib.sha384(sha384_encrypt.encode('utf-8')).hexdigest()
                        print ("[", sha384result, "]")
                elif hash == 'sha512':
                        sha512_encrypt = (input("sha512 encrypt = "))
                        sha512result = hashlib.sha512(sha512_encrypt.encode('utf-8')).hexdigest()
                        print ("[", sha512result, "]")
                elif hash == 'md5':
                        md5_encrypt = (input("md5 encrypt = "))
                        md5result = hashlib.md5(md5_encrypt.encode('utf-8')).hexdigest()
                        print ("[", md5result, "]")
                elif hash == 'blake2b':
                        blake2b_encrypt = (input("blake2b encrypt = "))
                        blake2bresult = hashlib.blake2b(blake2b_encrypt.encode('utf-8')).hexdigest()
                        print ("[", blake2bresult, "]")
                elif hash == 'blake2s':
                        blake2s_encrypt = (input("blake2s encrypt = "))
                        blake2sresult = hashlib.blake2s(blake2s_encrypt.encode('utf-8')).hexdigest()
                        print ("[", blake2sresult, "]")
                elif hash == 'sha3_224':
                        sha3_224_encrypt = (input("sha3_224 encrypt = "))
                        sha3_224result = hashlib.sha3_224(sha3_224_encrypt.encode('utf-8')).hexdigest()
                        print ("[", sha3_224result, "]")
                elif hash == 'sha3_256':
                        sha3_256_encrypt = (input("sha3_256 encrypt = "))
                        sha3_256result = hashlib.sha3_256(sha3_256_encrypt.encode('utf-8')).hexdigest()
                        print ("[", sha3_256result,"]")
                elif hash == 'sha3_512':
                        sha3_512_encrypt = (input("sha3_512 encrypt = "))
                        sha3_512result = hashlib.sha3_512(sha3_512_encrypt.encode('utf-8')).hexdigest()
                        print ("[", sha3_512result, "]")
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
                        continue #continue boleh dicode, boleh juga tidak dicode
                if exit == '2':
                        if hash == 'sha1':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[   sha1    ]" + " >\> " + "[ " + str(sha1result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                        if hash == 'sha224':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[   sha224  ]" + " >\> " + "[ " + str(sha224result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                        if hash == 'sha256':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[  sha256   ]" + " >\> " + "[ " + str(sha256result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                        if hash == 'sha384':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[   sha384  ]" + " >\> " + "[ " + str(sha384result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                        if hash == 'sha512':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[  sha512   ]" + " >\> " + "[ " + str(sha512result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                        if hash == 'md5':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[    md5    ]" + " >\> " + "[ " + str(md5result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                        if hash == 'blake2b':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[  blake2b  ]" + " >\> " + "[ " + str(blake2bresult) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                        if hash == 'blake2s':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[  blake2s  ]" + " >\> " + "[ " + str(blake2sresult) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                        if hash == 'shake_128':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[ shake_128 ]" + " >\> " + "[ " + str(shake_128result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                        if hash == 'shake_256':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[ shake_256 ]" + " >\> " + "[ " + str(shake_256result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                        if hash == 'sha3_224':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[ sha3_224  ]" + " >\> " + "[ " + str(sha3_224result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                        if hash == 'sha3_256':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[ sha3_256  ]" + " >\> " + "[ " + str(sha3_256result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                        if hash == 'sha3_512':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[ sha3_512  ]" + " >\> " + "[ " + str(sha3_512result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                continue
                if exit == '3':
                        clear = lambda: os.system('clear')
                        clear()
                        break
                if exit == '4':
                        if hash == 'sha1':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[   sha1    ]" + " >\> " + "[ " + str(sha1result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                        if hash == 'sha224':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[   sha224  ]" + " >\> " + "[ " + str(sha224result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                        if hash == 'sha256':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[  sha256   ]" + " >\> " + "[ " + str(sha256result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                        if hash == 'sha384':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[   sha384  ]" + " >\> " + "[ " + str(sha384result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                        if hash == 'sha512':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[  sha512   ]" + " >\> " + "[ " + str(sha512result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                        if hash == 'md5':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[    md5    ]" + " >\> " + "[ " + str(md5result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                        if hash == 'blake2b':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[  blake2b  ]" + " >\> " + "[ " + str(blake2bresult) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                        if hash == 'blake2s':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[  blake2s  ]" + " >\> " + "[ " + str(blake2sresult) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                        if hash == 'shake_128':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[ shake_128 ]" + " >\> " + "[ " + str(shake_128result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                        if hash == 'shake_256':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[ shake_256 ]" + " >\> " + "[ " + str(shake_256result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                        if hash == 'sha3_224':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[ sha3_224  ]" + " >\> " + "[ " + str(sha3_224result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                        if hash == 'sha3_256':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[ sha3_256  ]" + " >\> " + "[ " + str(sha3_256result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                        if hash == 'sha3_512':
                                encryptresult = open('encrypt-hash.txt', 'a+')
                                encryptresult.write("[ sha3_512  ]" + " >\> " + "[ " + str(sha3_512result) + " ]" + '\n')
                                encryptresult.close()
                                clear = lambda: os.system('clear')
                                clear()
                                break
                
except KeyboardInterrupt: #Keyboard Interrupt
                print("Makan ya Sayanggku")
finally:
        print("Sayangku Maniss")
