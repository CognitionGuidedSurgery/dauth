__author__ = 'weigl'

import rsa

(pubkey, privkey) = rsa.newkeys(4096, poolsize=16)

with open("key.private", 'wb') as fd:
    fd.write(privkey.save_pkcs1('PEM'))


with open('key.public', 'wb') as fd:
    fd.write(pubkey.save_pkcs1('PEM'))

