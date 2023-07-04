# Basé sur ces explications : https://stackoverflow.com/questions/29298346/xmpp-sasl-scram-sha1-authentication
import base64
import hashlib
import argparse
import hmac
from colorama import Fore

class XMPP_Brute_forcer():

	def __init__(self, wordlist, username, client_nonce, server_nonce, salt, proof, signature):
		self.ITERATION = 4096
		self.wordlist = wordlist
		self.username = username
		self.client_nonce = client_nonce
		self.server_nonce = server_nonce
		self.salt = salt
		self.proof = proof
		self.signature = signature

	def _hmac_sha1(self, key, salted):
		raw = salted.encode('utf-8')
		hashed = hmac.new(key,raw, hashlib.sha1)
		return hashed.hexdigest()

	def xor(self, s1, s2):
		unhex_s1, unhex_s2 = bytes.fromhex(s1), bytes.fromhex(s2)
		r = b""
		for i in range(len(unhex_s1)):
			r += (unhex_s1[i] ^ unhex_s2[i]).to_bytes()
		return r.hex()

	def check_password(self, password):
		password = password.strip()
		salted_password = hashlib.pbkdf2_hmac('sha1', password.encode(), base64.b64decode(self.salt),self.ITERATION)
		client_key = self._hmac_sha1(salted_password, "Client Key")
		stored_key = hashlib.sha1(bytes.fromhex(client_key)).hexdigest()
		auth_message = f"n={self.username},r={self.client_nonce},r={self.client_nonce}{self.server_nonce},s={self.salt},i={self.ITERATION},c=biws,r={self.client_nonce}{self.server_nonce}"
		client_signature = self._hmac_sha1(bytes.fromhex(stored_key), auth_message)
		client_proof = base64.b64encode(bytes.fromhex(self.xor(client_key, client_signature))).decode()
		server_key = self._hmac_sha1(salted_password, 'Server Key')
		server_signature = base64.b64encode(bytes.fromhex(self._hmac_sha1(bytes.fromhex(server_key),auth_message))).decode()

		if client_proof == self.proof or server_signature == self.signature:
			print(f"{Fore.GREEN}[+] Password found : {password}{Fore.RESET}")
			return True
		return False

	def brute_force(self):
		with open(self.wordlist, "r") as w:
			passwords = w.readlines()

		for password in passwords:
			flag = self.check_password(password)
			if flag:
				return flag

def banner(W,u,c_n,s_n,s,p,si):
	content = f"""
DDDDD          XX    XX MM    MM PPPPPP  PPPPPP  
DD  DD          XX  XX  MMM  MMM PP   PP PP   PP 
DD   DD _____    XXXX   MM MM MM PPPPPP  PPPPPP  
DD   DD         XX  XX  MM    MM PP      PP      
DDDDDD         XX    XX MM    MM PP      PP      

{Fore.CYAN}[+] Author : D0pp3lgang3r{Fore.RESET}
{Fore.WHITE}[+] Date : 04/07/2023{Fore.RESET}
{Fore.YELLOW}[*] Cracking XMPP password using :
             [>] Wordlist : {W}
             [>] Username : {u}
             [>] Client Nonce : {c_n}
             [>] Server Nonce : {s_n}
             [>] Salt : {s}
             [>] Proof : {p}
             [>] Signature : {si}
{Fore.RESET}
	"""
	return content

def parseArgs():
	parser = argparse.ArgumentParser(add_help=True, description='This tool allows you to retrieve the password of an XMPP authentication')
	parser.add_argument("--wordlist", dest="wordlist", required=True, help="Specify the wordlist with passwords you want to use.")
	parser.add_argument("--username", dest="username", required=True, help="Specify the username of the authentication")
	parser.add_argument("--client_nonce", dest="client_nonce", required=True, help="Specify the client nonce")
	parser.add_argument("--server_nonce", dest="server_nonce", required=True, help="Specify the server nonce")
	parser.add_argument("--salt", dest="salt", required=True, help="Specify the salt of the authentication")
	parser.add_argument("--proof", dest="proof", required=True, help="Specify the proof")
	parser.add_argument("--signature", dest="signature", required=True, help="Specify the server signature")
	args = parser.parse_args()
	return args

def main():	
	args = parseArgs()
	print(banner(args.wordlist, args.username, args.client_nonce, args.server_nonce, args.salt, args.proof, args.signature))
	xmpp = XMPP_Brute_forcer(args.wordlist, args.username, args.client_nonce, args.server_nonce, args.salt, args.proof, args.signature)
	if not xmpp.brute_force():
		print(f"{Fore.RED}[-] Password not found :({Fore.RESET}")

if __name__ == "__main__":
	main()
# python .\d_xmpp.py --wordlist .\temp.txt --username user --client_nonce fyko+d2lbbFgONRv9qkxdawL --server_nonce 3rfcNHYJY1ZVvWVs7j --salt QSXCR+Q6sek8bf92 --proof v0X8v3Bz2T0CJGbJQyF0X+HI4Ts= --signature rmF9pqV8S7suAoZWja4dJRkFsKQ=