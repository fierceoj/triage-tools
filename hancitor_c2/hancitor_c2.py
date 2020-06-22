#!/usr/bin/env python3

#tool to decode hancitor post-infection c2 traffic 
#extracts additional c2 iocs

import base64
import sys
import re


def hancitor_decode(encoded_traffic):
	decoded_b64 = base64.b64decode(encoded_traffic)
	decoded_traffic = ''.join([chr(i^0x7a) for i in decoded_b64])
	sanitized_decoded_traffic = sanitize(decoded_traffic)
	return sanitized_decoded_traffic

def sanitize(decoded_traffic):
	sanitized = re.sub(r'http:\/\/', 'hxxp://', decoded_traffic, flags=re.IGNORECASE)
	sanitized = re.sub(r'https:\/\/', 'hxxps://', sanitized, flags=re.IGNORECASE)
	sanitized = re.sub(r'\.', '[.]', sanitized, flags=re.IGNORECASE)
	return sanitized

def print_iocs(sanitized_decoded_traffic):
	iocs = re.findall(r'hxxps?:\/\/[^|}]+', sanitized_decoded_traffic)
	iocs = '\n'.join(iocs)
	return iocs


def main():

	if len(sys.argv) is not 2:
		sys.exit("Usage: python3 hancitor_c2.py <encoded_traffic>")

	else:
		encoded_traffic = str(sys.argv[1])
		sanitized_decoded_traffic = hancitor_decode(encoded_traffic)
		print('\n=================================================================================')
		print('****************************** DECODED TRAFFIC **********************************')
		print('=================================================================================')
		print(sanitized_decoded_traffic)

		iocs = print_iocs(sanitized_decoded_traffic)
		print('\n=================================================================================')
		print('************************************ IOCs ***************************************')
		print('=================================================================================')
		print(iocs)
		print('\n')



