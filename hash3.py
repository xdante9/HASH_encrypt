import hashlib #import lib

while True:
        hash = (input('''|----------<<<<<[]>>>>>----------|
| [   sha1    ]    [   sha224  ] |
| [  sha384   ]    [   sha256  ] |
| [  sha512   ]    [    md5    ] |
| [  blake2b  ]    [  blake2s  ] |
| [ shake_128 ]    [ shake_256 ] |
| [ sha3_224  ]    [ sha3_256  ] |
| [ sha3_512  ]                  |
|----------<<<<<[]>>>>>----------|
select hash: '''))
        if hash == 'sha1':
                sha1_encrypt = (input("sha1 encrypt = ")) #input string
                print ("[",hashlib.sha1(sha1_encrypt.encode('utf-8')).hexdigest(),"]")#output md5 encrypt
        elif hash == 'sha224':
                sha224_encrypt = (input("sha224 encrypt = ")) #input string
                print ("[",hashlib.sha224(sha224_encrypt.encode('utf-8')).hexdigest(),"]") #output sha224 encrypt
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

        exit = input('''<<<<<<<[]>>>>>>>
[ 1.restart ]
[ 2.exit ]
>\> ''')
        if exit == '2':
                break
        
