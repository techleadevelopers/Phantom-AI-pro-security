# generate_keypair.py
from Crypto.PublicKey import RSA

key = RSA.generate(2048)

with open("private.pem", "wb") as priv_file:
    priv_file.write(key.export_key())

with open("public.pem", "wb") as pub_file:
    pub_file.write(key.publickey().export_key())

print("[✅] Novo par RSA gerado com sucesso!")
