import hashlib #import lib
import copy
import clipboard


while True:
        hash = (raw_input('''|--------<<<<<[]>>>>>--------|
|  [  sha1  ]    [ sha224 ]  |
|  [ sha384 ]    [ sha256 ]  |
|  [ sha512 ]    [   md5  ]  |
|--------<<<<<[]>>>>>--------|
select hash: '''))
        if hash == 'sha1':
                sha1_encrypt = (raw_input("sha1 encrypt = ")) #input string
                print "[",hashlib.sha1(sha1_encrypt).hexdigest(),"]"#output md5 encrypt
        if hash == 'sha224':
                sha224_encrypt = (raw_input("sha224 encrypt = ")) #input string
                print "[",hashlib.sha224(sha224_encrypt).hexdigest(),"]" #output sha224 encrypt
        if hash == 'sha384':
                sha384_encrypt = (raw_input("sha384_encrypt = "))
                print "[",hashlib.sha384(sha384_encrypt).hexdigest(),"]"
        if hash == 'sha256':
                sha256_encrypt = (raw_input("sha256 encrypt = "))
                print "[",hashlib.sha256(sha256_encrypt).hexdigest(),"]"
        if hash == 'sha512':
                sha512_encrypt = (raw_input("sha512 encrypt = "))
                print "[",hashlib.sha512(sha512_encrypt).hexdigest(),"]"
        if hash == 'md5':
                md5_encrypt = (raw_input("md5 encrypt = "))
                print "[",hashlib.md5(md5_encrypt).hexdigest(),"]"
                
        exit = raw_input('''<<<<<[]>>>>>
[ 1.restart ]
[ 2.exit ]
>\> ''')
        if exit == '2':
                break

        
