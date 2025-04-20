from Crypto.PublicKey import RSA

# Gera chave RSA 2048 bits
key = RSA.generate(2048)

# Salva chave privada
with open("private.pem", "wb") as f:
    f.write(key.export_key())

# Salva chave pública
with open("public.pem", "wb") as f:
    f.write(key.publickey().export_key())

print("[+] Chaves RSA geradas com sucesso.")
