# builder/keygen.py

from Crypto.PublicKey import RSA

def generate_keypair(public_path="public.pem", private_path="private.pem", bits=2048):
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(private_path, "wb") as priv_file:
        priv_file.write(private_key)

    with open(public_path, "wb") as pub_file:
        pub_file.write(public_key)

    print("[✅] Novo par RSA gerado com sucesso!")
