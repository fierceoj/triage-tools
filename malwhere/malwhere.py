#!/usr/bin/env python3

#simple tool to analyze encoded, compressed, or obfuscated payloads
#find concealed malicious content and IOCs
#obtain IOCs in sanitized or desanitized format


import re
import sys
import argparse
import gzip
import base64
import binascii
from urllib.parse import unquote
from email.header import decode_header, make_header

#check encoded data for encoding pattern matches 
#does not support file input
def check_encoding(encoded_data):
	decoded_data = ''

	#base64 pattern 
	b64_pattern = re.search(r'^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$', encoded_data)
	#binary pattern
	bin_pattern = all(ch in '01' for ch in encoded_data.replace(' ', ''))
	#hex pattern 
	hex_pattern = all(ch in '0123456789abcdefABCDEF' for ch in encoded_data.replace(' ', ''))
	#url(percent) encoding pattern 
	url_enc_pattern = re.search(r'%[\w\d]{2}', encoded_data)
	#MIME encoded-word header pattern 
	mime_enc_wd_pattern = re.search(r'(\=\?.*\?(B|Q)\?.*\?\=)+', encoded_data)

	#check if base64 encoded
	if (b64_pattern):	
		try:
			base64.b64decode(encoded_data)
			print('\n[*] Match: base64 encoding')

			#check if gzipped then base64 encoded
			if encoded_data.startswith('H4sI'):
				print('[*] Match: gzip compression + base64 encoding')
				decoded_data = b64_gunzip(encoded_data)

			else:
				#check if it can base64 utf-16 / utf-8 decoded
				try:
					decoded_data = b64_utf16(encoded_data)
					print('[*] Match: base64 utf-16 encoding')
				except:
					pass
				try:
					decoded_data = b64_utf8(encoded_data)
					print('[*] Match: base64 utf-8 encoding')
				except:
					pass
		except:
			pass	

	#check if binary string:
	elif (bin_pattern):
		try:
			decoded_data = bin_decode(encoded_data)
			print('\n[*] Match: binary encoding')
		except:
			pass

	#check if hex encoded
	elif (hex_pattern):
		#check if gzipped then hex encoded
		if encoded_data.replace(' ', '').startswith('1f8b0800'):
			decoded_data = hex_gunzip(encoded_data)
			print('\n[*] Match: gzip compression + hex encoding')

		#else confirm if normal hex encoded
		else: 
			try:
				decoded_data = hex_decode(encoded_data)
				print('\n[*] Match: hex encoding')
			except:
				pass
	
	#check if url(percent) encoded 
	elif (url_enc_pattern):
		try:
			decoded_data = url_decode(encoded_data)
			print('\n[*] Match: URL (percent) encoding')
		except:
			pass

	#check for MIME encoded-word 
	elif (mime_enc_wd_pattern):
		try:
			decoded_data = header_decode(encoded_data)
			print('\n[*] Match: MIME encoded-word header')
		except:
			pass

	else:
		#check if rot13 encoded
		#letter frequency order is based on Cornell study on Englisth language letter frequencies
		#http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
		#descending frequency order = etaoinsrhdlucmfywgpbvkxqjz
		total_letters = len(re.findall(r'[a-z]', encoded_data.lower()))

		#must contain a sufficient sampling of letters to continue checking for rot13 encoding
		if total_letters > 100:

			#use corresponding rot13 letters 
			#rot13(etaoinsrhdlucmfywgpbvkxqjz) = rgnbvafeuqyhpzsljtcoixkdwm
			high_freq_letters = ['r', 'g', 'n', 'b', 'v']
			high_freq = {key:(encoded_data.count(key)/total_letters) for key in high_freq_letters}

			midhigh_freq_letters = ['a', 'f', 'e', 'u', 'q']
			midhigh_freq = {key:(encoded_data.count(key)/total_letters) for key in midhigh_freq_letters}

			mid_freq_letters = ['y', 'h', 'p', 'z', 's']
			mid_freq = {key:(encoded_data.count(key)/total_letters) for key in mid_freq_letters}

			midlow_freq_letters = ['l', 'j', 't', 'c', 'o', 'i']
			midlow_freq = {key:(encoded_data.count(key)/total_letters) for key in midlow_freq_letters}

			low_freq_letters = ['x', 'k', 'd', 'w', 'm']
			low_freq = {key:(encoded_data.count(key)/total_letters) for key in low_freq_letters}
	
			#average frequencies of each letter frequency category
			high_freq_avg = sum(high_freq.values())/len(high_freq.values())
			midhigh_freq_avg = sum(midhigh_freq.values())/len(midhigh_freq.values())
			mid_freq_avg = sum(mid_freq.values())/len(mid_freq.values())
			midlow_freq_avg = sum(midlow_freq.values())/len(midlow_freq.values())
			low_freq_avg = sum(low_freq.values())/len(low_freq.values())

			correct_high_freq_avg = False
			correct_midhigh_freq_avg = False
			correct_mid_freq_avg = False
			correct_midlow_freq_avg = False
			correct_low_freq_avg = False

			#check if each frequency category is in expected range
			if .0685 <= high_freq_avg <= .1085 :
				correct_high_freq_avg = True
			if .049 <= midhigh_freq_avg <= .069:
				correct_midhigh_freq_avg = True
			if .019 <= mid_freq_avg <= .039:
				correct_mid_freq_avg = True
			if .0078 <= midlow_freq_avg <= .0278:
				correct_midlow_freq_avg = True
			if low_freq_avg <= .01:
				correct_low_freq_avg = True

			freq_avgs = [correct_high_freq_avg, correct_midhigh_freq_avg, correct_mid_freq_avg, correct_midlow_freq_avg, correct_low_freq_avg]

			if all(freq_avgs):
				try:
					decoded_data = rot13_decode(encoded_data)
					print('\n[*] Match: rot13 encoding')
					print('\t- High freq values avg: ' + str(high_freq_avg))
					print('\t- Midhigh freq values avg: ' + str(midhigh_freq_avg))
					print('\t- Mid freq values avg: ' + str(mid_freq_avg))
					print('\t- Midlow freq values avg: ' + str(midlow_freq_avg))
					print('\t- Low freq values avg: ' + str(low_freq_avg))
				except:
					pass

	
	return decoded_data


#decode a non-Unicode base64-encoded string
def b64_decode(encoded_data):
	try:
		decoded_data = base64.b64decode(encoded_data)
		return decoded_data
	except:
		sys.exit('Decoding error.')

#decode a base64 utf-8 encoded string
def b64_utf8(encoded_data):
	try:
		decoded_data = base64.b64decode(encoded_data).decode('UTF-8')
		return decoded_data
	except:
		sys.exit('Decoding error.')

#decode a base64 utf-16 encoded string
def b64_utf16(encoded_data):
	try:
		decoded_data = base64.b64decode(encoded_data).decode('UTF-16')
		return decoded_data
	except:
		sys.exit('Decoding error.')

#reverse data that has been gzip compressed and then base64 encoded
#gzip + base64 is a common tactic for obfuscating PowerShell payloads
def b64_gunzip(encoded_data):
	try:
		decoded_data = gzip.decompress(base64.b64decode(encoded_data)).decode()
		return decoded_data
	except:
		sys.exit('Decoding/decompression error.')

#decode hex-encoded data to ascii
def hex_decode(encoded_data):
	try:
		decoded_data = bytes.fromhex(encoded_data).decode('ascii')
		return decoded_data
	except:
		sys.exit('Decoding error.')

#reverse data that has been gzip compressed and then hex encoded
def hex_gunzip(encoded_data):
	try:
		decoded_data = gzip.decompress(bytes.fromhex(encoded_data)).decode()
		return decoded_data
	except:
		sys.exit('Decoding/decompression error.')

#decode url(percent) encoding
#useful for analyzing web app attacks
def url_decode(encoded_data):
	try:
		decoded_data = unquote(encoded_data)
		return decoded_data
	except:
		sys.exit('Decoding error.')

#decode binary encoding (bits) to ascii
def bin_decode(encoded_data):
	try:
		if not encoded_data.startswith('0b'):
			encoded_data = ('0b', encoded_data)
			encoded_data = ''.join(encoded_data)
		encoded_data = encoded_data.replace(' ', '')
		n = int(encoded_data, 2)
		decoded_data = binascii.unhexlify('%x' % n).decode('ascii')
		return decoded_data
	except:
		sys.exit('Decoding error.')

#decode rot13 
def rot13_decode(encoded_data):
	try:
		rot13_table = encoded_data.maketrans('ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz', 'NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm')
		decoded_data = encoded_data.translate(rot13_table)
		return decoded_data
	except:
		sys.exit('Decoding error.')

#provide a key to decode xor-encoded data (decimal key)
def xor_key(key, encoded_data):
	decoded_data = ''
	for i in encoded_data:
		decoded_data += chr(ord(i) ^ key)
	return decoded_data

#decode xor-encoded data by brute force
#one-byte key iterations, 15 keys ata a time
def xor_brute(encoded_data):
	low_key = 1
	high_key = 16
	while high_key < 257:
		for k in range (low_key, high_key):
			decoded_data = xor_key(k, encoded_data)
			print(f'KEY: {k} : ' + str(decoded_data))
		print('\nMORE KEYS?')
		print('1\tY')
		print('2\tN')
		check_more_keys = int(input('\nSELECTION: '))
		if check_more_keys == 1:
			low_key = high_key
			high_key += 15
		elif check_more_keys == 2:
			sys.exit(0)
		else:
			print('\nError: Please select 1 or 2\n')

#decode MIME encoded-word headers
def header_decode(encoded_data):
	try:
		decoded_data = str(make_header(decode_header(encoded_data)))
		return decoded_data
	except:
		sys.exit('Decoding error.')

#decompress a gzipped file
def gzip_decompress_file(encoded_data):
	try:
		f = gzip.open(encoded_data, 'rb')
		decoded_data = f.read().decode()
		f.close()
		return decoded_data
	except:
		sys.exit('Decompression error.')

#sanitize results
def sanitize(decoded_data):
	decoded_data = re.sub(r'http:\/\/', 'hxxp://', decoded_data)
	decoded_data = re.sub(r'https:\/\/', 'hxxps://', decoded_data)
	decoded_data = re.sub(r'\.(?=([a-zA-Z]{2}|[a-zA-Z]{3}|[a-zA-Z]{4}|[a-zA-Z]{5}|[a-zA-Z]{6}|[a-zA-Z]{7}|[a-zA-Z]{8}|[a-zA-Z]{9}|[a-zA-Z]{10}|\d{1}|\d{2}|\d{3}))', '[.]', decoded_data)
	return decoded_data

#extract and print urls
def print_urls(decoded_data, sanitized=True):
	print('\nURLs: ')
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
	decoded_data = ''

	#this is a python3 script
	if sys.version.startswith('2'):
		sys.exit('You must use python3 to run this script.')

	main_parser = argparse.ArgumentParser(description='Decode, decompress, and deobfuscate malicious payloads and indicators.')

	main_parser.add_argument('--check', '-c', dest='check_enc', action='store', help='detect encoding/compression/obfuscation methods')
	main_parser.add_argument('--base64', '-b64', dest='b64_str', action='store', help='decode base64 (non-Unicode)')
	main_parser.add_argument('--base64_utf8', '-b8', dest='b64_utf8_str', action='store', help='decode base64 (UTF-8)')
	main_parser.add_argument('--base64_utf16', '-b16', dest='b64_utf16_str', action='store', help='decode base64 (UTF-16)')
	main_parser.add_argument('--base64_gunzip', '-bg', dest='b64_gzip_str', action='store', help='decode base64-encoded gzip compression')
	main_parser.add_argument('--hex', '-hx', dest='hex_str', action='store', help='decode hex to ascii')
	main_parser.add_argument('--hex_gunzip', '-hg', dest='hex_gzip_str', action='store', help='decode hex-encoded gzip compression')
	main_parser.add_argument('--url', '-u', dest='url_str', action='store', help='decode URL(percent) encoding')
	main_parser.add_argument('--bin', '-b', dest='bin_str', action='store', help='decode binary to ascii')
	main_parser.add_argument('--rot13', '-r', dest='rot13_str', action='store', help='decode rot13')
	main_parser.add_argument('--xor', '-x', dest='xorkey', action='store', help='decode XOR with a given key')
	main_parser.add_argument('--xor_bf', '-xbf', dest='xor_bf', action='store_const', const='xor_bf', help='decode XOR by brute force')
	main_parser.add_argument('--header', '-hdr', dest='email_header', action='store', help='decode MIME encoded-word headers')
	main_parser.add_argument('--gunzip', '-gz', dest='gzipped_file', action='store', help='decompress gzipped file')
	main_parser.add_argument('--desan', '-d', dest='desanitize', action='store_const', const='desanitize', help='show desanitized results')
	main_parser.add_argument('--ioc', '-i', dest='iocs', action='store', help='extract URLs and IPs')


	args = main_parser.parse_args()

	#check args and do stuff based on args
	if args.check_enc:
		encoded_data = args.check_enc
		decoded_data = check_encoding(encoded_data)

		if not decoded_data:
			sys.exit('No encoding match found')

		while decoded_data:
			save_decoded_data = decoded_data
			decoded_data = check_encoding(decoded_data)
		
		decoded_data = save_decoded_data

	elif args.b64_str:
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
		decoded_data = b64_gunzip(encoded_data)
	elif args.hex_str:
		encoded_data = args.hex_str
		decoded_data = hex_decode(encoded_data)
	elif args.hex_gzip_str:
		encoded_data = args.hex_gzip_str
		decoded_data = hex_gunzip(encoded_data)
	elif args.url_str:
		encoded_data = args.url_str
		decoded_data = url_decode(encoded_data)
	elif args.bin_str:
		encoded_data = args.bin_str
		decoded_data = bin_decode(encoded_data)
	elif args.rot13_str:
		encoded_data = args.rot13_str
		decoded_data = rot13_decode(encoded_data)
	elif args.xorkey:
		key = int(args.xorkey, 0)
		encoded_data = input('\nXORed Data: ')
		decoded_data = xor_key(key, encoded_data)
	elif args.xor_bf == 'xor_bf':
		encoded_data = input('\nXORed Data: ')
		xor_brute(encoded_data)
	elif args.email_header:
		encoded_data = args.email_header
		decoded_data = header_decode(encoded_data)
	elif args.gzipped_file:
		encoded_data = args.gzipped_file
		decoded_data = gzip_decompress_file(encoded_data)
	elif args.iocs:
		if str(args.iocs).endswith('.csv') or str(args.iocs).endswith('.txt'):
			filename = args.ioc_contents
			with open(filename, 'r') as f:
				decoded_data = f.read()
		else:
			decoded_data = args.iocs 
	else:
		sys.exit('Help: python3 malwhere.py -h')

	#print results 
	if not args.iocs:
		print("\n=========================================================")
		print('********************     DECODED     ********************')
		print("=========================================================\n")
		print(decoded_data)
	if not args.b64_str:
		if args.desanitize == 'desanitize':
			print_urls(decoded_data, sanitized=False)
			print_ips(decoded_data, sanitized=False)
		else:
			decoded_data = sanitize(decoded_data)
			print_urls(decoded_data, sanitized=True)
			print_ips(decoded_data, sanitized=True)


if __name__ == "__main__":
	main()
