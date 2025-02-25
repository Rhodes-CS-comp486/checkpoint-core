from Crypto.PublicKey import RSA

ServerKey = RSA.generate(2048)

pwd = 'checkpt-core'
with open("src\secretkey.pem", "wb") as f:
    ServerKeyPair = ServerKey.export_key(passphrase=pwd)
    f.write(ServerKeyPair)
    f.close()

with open("src\publickey.pem", "wb") as f:
    PublicKey = ServerKey.public_key().export_key()
    f.write(PublicKey)
    f.close()