# test_encrypt.py
from core.encryptor import encrypt_file
import os

uid = "TESTEUIDBRUTAL999"
public_key_path = "public.pem"
input_file = "samples/teste_brutal.txt"
output_dir = "output/"

encrypt_file(input_file, public_key_path, uid, output_dir)
