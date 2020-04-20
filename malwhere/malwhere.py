#!/usr/bin/env python3

#simple tool to analyze encoded, obfuscated, or compressed payloads and IOCs
#find concealed malicious content and IOCs
#obtain results in sanitized or desanitized format

import re
import sys
import argparse
import gzip
import zlib
import base64
from urllib.parse import unquote
from email.header import Header, decode_header, make_header

#decode a non-Unicode base64-encoded string
def b64_decode(encoded_data):
	decoded_data = base64.b64decode(encoded_data).decode('ascii')
	return decoded_data

#decode a base64 utf-8 encoded string
def b64_utf8(encoded_data):
	decoded_data = base64.b64decode(encoded_data).decode('UTF-8')
	return decoded_data

#decode a base64 utf-16 encoded string
def b64_utf16(encoded_data):
	decoded_data = base64.b64decode(encoded_data).decode('UTF-16')
	return decoded_data

#reverse data that has been gzip compressed and then base64 encoded
#common tactic for obfuscating payloads
def b64_gzip(encoded_data):
	decoded_data = gzip.decompress(base64.b64decode(encoded_data)).decode()
	return decoded_data

#decode hex-encoded data to ascii
def hex_decode(encoded_data):
	decoded_data = bytes.fromhex(encoded_data).decode('ascii')
	return decoded_data

#decode url(percent) encoding
#useful for analyzing web app attacks
def url_decode(encoded_data):
	decoded_data = unquote(encoded_data)
	return decoded_data

#decode binary encoding to ascii
def bin_decode(encoded_data):
	pass

#provide a key to decode xor-encoded data (decimal key)
def xor_with_key(key, encoded_data):
	decoded_data = ''
	for i in encoded_data:
		decoded_data += chr(ord(i) ^ key)
	return decoded_data

#decode xor-encoded data by brute force
#one-byte key iterations
def xor_brute_one_byte(encoded_data):
	low_key = 1
	high_key = 16
	while high_key < 257:
		for k in range (low_key, high_key):
			decoded_data = xor_with_key(k, encoded_data)
			print(f'KEY: {k} : ' + str(decoded_data))
		print('\nMORE KEYS?')
		print('1\tY')
		print('2\tN')
		check_more_keys = int(input('\nSELECTION: '))
		if check_more_keys == 1:
			low_key = high_key
			high_key += 15
		else:
			return

#decode MIME encoded-word headers
def header_decode(encoded_data):
	decoded_data = make_header(decode_header(encoded_data))
	return decoded_data

#decompress gzipped data
def gzip_decompress():
	pass

#decompress a gzipped file
def gzip_decompress_file():
	pass

#do something with zlib here
#maybe flatdecode for pdfs?
def zlib_something():
	pass

#sanitize results
def sanitize(decoded_data):
	decoded_data = re.sub(r'http:\/\/', 'hxxp://', decoded_data)
	decoded_data = re.sub(r'https:\/\/', 'hxxps://', decoded_data)
	decoded_data = re.sub(r'\.(?=([a-zA-Z]{2}|[a-zA-Z]{3}|[a-zA-Z]{4}|[a-zA-Z]{5}|[a-zA-Z]{6}|[a-zA-Z]{7}|[a-zA-Z]{8}|[a-zA-Z]{9}|[a-zA-Z]{10}|\d{1}|\d{2}|\d{3}))', '[.]', decoded_data)
	return decoded_data

#extract and print urls
def print_urls(decoded_data, sanitized=True):
	print('URLs: ')
	if sanitized:
		match_url = re.findall(r'hxxps?:\/\/[^\)\s]+', decoded_data)
		match_url = '\n'.join(match_url)
	else:
		match_url = re.findall(r'https?:\/\/[^\)\s]+', decoded_data)
		match_url = '\n'.join(match_url)
	print(match_url)

#extract and print IPs
def print_ips(decoded_data, sanitized=True):
	print('\nIPs: ')
	if sanitized:
		match_ip = re.findall(r'\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}', decoded_data)
		match_ip = '\n'.join(match_ip)
	else:
		match_ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', decoded_data)
		match_ip = '\n'.join(match_ip)
	print(match_ip)


#main
def main():
	if sys.version.startswith('2'):
		sys.exit('You must use python3 to run this script.')

	main_parser = argparse.ArgumentParser(description='Decode, decompress, and deobfuscate malicious payloads and IOCs.')

	main_parser.add_argument('--base64', '-b', dest='b64_str', action='store', help='decode base64 (non-Unicode)')
	main_parser.add_argument('--base64_utf8', '-b8', dest='b64_utf8_str', action='store', help='decode base64 (UTF-8)')
	main_parser.add_argument('--base64_utf16', '-b16', dest='b64_utf16_str', action='store', help='decode base64 (UTF-16)')
	main_parser.add_argument('--base64_gzip', '-bg', dest='b64_gzip_str', action='store', help='decode base64-encoded gzip compression')
	main_parser.add_argument('--hex', '-hx', dest='hex_str', action='store', help='decode hex to ascii')
	main_parser.add_argument('--url', '-u', dest='url_str', action='store', help='decode URL(percent) encoding')
	#binascii parser for bin_decode()?
	main_parser.add_argument('--xor', '-x', dest='xorkey_and_data', action='store', nargs=2, help='decode XOR with a provided key')
	main_parser.add_argument('--xor_bf', '-xbf', dest='xored_data', action='store', help='decode XOR by brute force')
	main_parser.add_argument('--header', '-hdr', dest='email_header', action='store', help='decode MIME encoded-word headers')

	main_parser.add_argument('--desan', '-d', dest='desanitize', action='store_const', const='desanitize', help='show desanitized results only')



	args = main_parser.parse_args()

	#get decoding arguments
	if args.b64_str:
		encoded_data = args.b64_str
		decoded_data = b64_decode(encoded_data)
	elif args.b64_utf8_str:
		encoded_data = args.b64_utf8_str
		decoded_data = b64_utf8(encoded_data)
	elif args.b64_utf16_str:
		encoded_data = args.b64_utf16_str
		decoded_data = b64_utf16(encoded_data)
	elif args.b64_gzip_str:
		encoded_data = args.b64_gzip_str
		decoded_data = b64_gzip(encoded_data)
	elif args.hex_str:
		encoded_data = args.hex_str
		decoded_data = hex_decode(encoded_data)
	elif args.url_str:
		encoded_data = args.url_str
		decoded_data = url_decode(encoded_data)
	elif args.xorkey_and_data:
		key = int(args.xorkey_and_data[0], 0)
		encoded_data = args.xorkey_and_data[1]
		decoded_data = xor_with_key(key, encoded_data)
	elif args.xored_data:
		encoded_data = args.xored_data
		xor_brute_one_byte(encoded_data)
	elif args.email_header:
		encoded_data = args.email_header
		decoded_data = header_decode(encoded_data)
	else:
		sys.exit('For help: python3 mal_where.py -h')

	#desanitize or sanitize
	#extract URLs and IPs
	if not args.xored_data:
		if args.desanitize == 'desanitize':
			print('\nDECODED: ')
			print(decoded_data)
			print_urls(decoded_data, sanitized=False)
			print_ips(decoded_data, sanitized=False)
		else:
			decoded_data = sanitize(decoded_data)
			print('\nDECODED AND SANITIZED: ')
			print(decoded_data)
			print_urls(decoded_data, sanitized=True)
			print_ips(decoded_data, sanitized=True)



if __name__ == "__main__":
	main()
