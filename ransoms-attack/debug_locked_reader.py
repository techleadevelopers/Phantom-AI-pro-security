import sys

def inspect_locked_file(path):
    with open(path, 'rb') as f:
        magic = f.read(6)
        print(f"[🔎] Magic bytes: {magic}")

        rsa_key = f.read(256)
        print(f"[🔎] RSA encrypted AES key size: {len(rsa_key)} bytes")

        iv = f.read(16)
        print(f"[🔎] IV: {iv.hex()} (size: {len(iv)})")

        ciphertext = f.read()
        print(f"[🔎] AES ciphertext size: {len(ciphertext)} bytes")

    total = 6 + len(rsa_key) + len(iv) + len(ciphertext)
    print(f"\n[📦] Total size: {total} bytes")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python debug_locked_reader.py <arquivo.locked>")
    else:
        inspect_locked_file(sys.argv[1])
