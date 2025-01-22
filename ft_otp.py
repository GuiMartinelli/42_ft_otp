import argparse, re, hashlib, hmac, struct, pyotp, base64
from cryptography.fernet import Fernet
from datetime import datetime, timezone

secret = b"fSyAsfzJoz6OGpLgJk8rY9Km64Q1UTpvgVco1ExWW0E="

def program_args():
	parser = argparse.ArgumentParser(description="A TOTP Generator")
	group = parser.add_mutually_exclusive_group()
	parser.add_argument('file', type=str, help="The file containing hexadecimal key to use")
	group.add_argument('-g', action="store_true")
	group.add_argument('-k', action="store_true")
	return parser.parse_args()


def open_file(path: str):
	try:
		with open(path, "rb") as file:
			return (file.read())
	except:
		print("Error: Something wrong while opening the file.")
		exit()


def validate_hex_key(key: str):
	return len(key) >= 64 and bool(re.fullmatch(b"[0-9a-fA-F]+", key))


def encrypt_key(key: str):
	fernet = Fernet(secret)
	return fernet.encrypt(key)


def decrypt_key(key: str):
	fernet = Fernet(secret)
	return fernet.decrypt(key)


def store_hexadecimal_key(file: str):
	hex_key = open_file(file)
	if validate_hex_key(hex_key):
		encrypted_key = encrypt_key(hex_key)
		with open("ft_otp.key", "wb") as file:
			file.write(encrypted_key)
		print("Key was successfully saved in ft_otp.key")
	else:
		print("Error: key must be 64 hexadecimal characters.")
	return()


def generate_dynamic_truncation(mac):
	hdig = mac.hexdigest()
	offset = int(hdig[-1], 16)
	p = hdig[offset * 2 : offset * 2 + 8]
	return int(p, 16) & 0x7fffffff


def generate_totp(key):
	time = int(datetime.now(timezone.utc).timestamp()) // 30
	mac = hmac.new(key, struct.pack(">Q", time), hashlib.sha1)
	dt = generate_dynamic_truncation(mac)
	return "{:06}".format(dt % 10 ** 6)


def generate_pyotp_totp(key):
	return (pyotp.TOTP(base64.b32encode(key)).now())

def generate_token(file: str):
	hex_key = open_file(file)
	key = decrypt_key(hex_key)

	otp = generate_totp(key)
	pyotp = generate_pyotp_totp(key)

	print("ft_otp generated token:\t{}\npyotp generated token:\t{}".format(otp, pyotp))
	return()


def main():
	args = program_args()
	if args.g:
		store_hexadecimal_key(args.file)
	if args.k:
		generate_token(args.file)


if __name__ == '__main__':
	main()