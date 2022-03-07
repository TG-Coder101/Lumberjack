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

    	#other imports
    	from datetime import datetime
    	from pprint import pprint
    	from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, SUBTREE, NTLM, BASE, ALL_ATTRIBUTES, Entry, Attribute, ServerPool
    	from ldap3.core.exceptions import LDAPBindError, LDAPException
    	from time import sleep
    	from rich.console import Console
    	from termcolor import colored, cprint
    	from rich.console import Theme
    	from pyfiglet import Figlet
except Exception as e:
    	print ("Error {}".format(e))

"""
lumberjack.py
"""

custom_theme = Theme({"success": "cyan", "error": "red", "warning": "yellow", "status": "green", "info": "purple"})
console = Console(theme=custom_theme)
LDAP_BASE_DN = 'DC=hacklabtest,DC=local'

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
		self.ldaps = ldaps
		self.ldap = ldap
		self.dPassword = password
		self.noCreds = no_credentials
		self.status = status
		self.verbose = verbose
		self.fuzz = fuzz
		
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
				console.print("[Success] Connected to Active Directory through LDAPs", style = "success")
			#Connect through LDAP
			elif self.ldap:
				self.server_pool = ServerPool(self.dIP)
				self.server = Server(self.dc, get_info=ALL)
				self.server_pool.add(self.server)
				self.conn = Connection(self.server_pool, self.dUser, password=self.dPassword, auto_bind=True, auto_referrals = False, fast_decoder=True)
				self.conn.open()
				self.conn.bind()
				console.print("[Success] Connected to Active Directory through LDAP", style = "success")
			#Connect through LDAPS without Credentials
			elif self.no_Creds & self.ldaps:
				self.dUser = ''
				self.dPassword = ''
				self.server_pool = ServerPool(self.dIP)
				self.server = Server(self.dc, port=646, use_ssl=True, get_info=ALL)
				self.server_pool.add(self.server)
				self.conn = Connection(self.server_pool, user=self.dUser, password=self.dPassword, fast_decoder=True, auto_bind=True,
							auto_referrals=True, check_names=False, read_only=True, lazy=False, raise_exceptions=False)
				self.conn.open()
				self.conn.bind()
				console.print("[Success] Connected to Active Directory through LDAPS and without credentials", style = "success")
			#Connect through LDAP without Credentials
			elif self.no_Creds & self.ldap:
				self.dUser = ''
				self.dPassword = ''
				self.server_pool = ServerPool(self.dIP)
				self.server = Server(self.dc, get_info=ALL)
				self.conn = Connection(self.server_pool, auto_bind=True, auto_referrals = False, fast_decoder=True)
				self.conn.open()
				self.conn.bind()
				console.print("[Success] Connected to Active Directory through LDAP and without credentials", style = "success")            			
			else :
				sleep(1)
				console.print ("[Error] Failed to connect: ", style = "error")
				raise LDAPBindError	
		except Exception as e:
			console.print ("[Error] Failed to connect: {} ".format(e), style = "error")
			raise LDAPBindError
			
	# Get the IP address of the domain controller		
	def getDC_IP(self, domainController):		

		try:
			ip_address = socket.gethostbyname(domainController)
			console.print("[Success] IP address of the domain is {}".format(ip_address))
		except:
			console.print("[Error] Unable to locate IP Address of Domain Controller through host lookup. Please try again", style = "error")            			
			sys.exit(1)

		self.dIP = ip_address
	
	# Get the IP address of the domain name		
	def getDCName(self):		
 		try:
			domainController = socket.gethostname()
			console.print("[Success] Domain Name is {}".format(domainController))
		except:
			console.print("[Error] Unable to locate Domain Name through host lookup. Please try again", style = "error")            			
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
				console.print ("[Success] Got all domain users ", style = "success")
				console.print('Found {0} user accounts'.format(len(self.conn.entries)), style = "info")
				pprint(self.conn.entries)	
			else:
				uAttributes = ['uid', 'sn', 'givenName', 'mail', 'uidNumber', 'sn', 'cn']
				self.conn.search(search_base=LDAP_BASE_DN, search_filter='(objectCategory=person)', search_scope=SUBTREE, attributes = uAttributes, size_limit=0)
				console.print ("[Success] Got all domain users ", style = "success")
				console.print('Found {0} user accounts'.format(len(self.conn.entries)), style = "info")
				pprint(self.conn.entries)
		except LDAPException as e:
			console.print ("[Warning] No Users found", style = "warning")
			pprint ("Error {}".format(e))
			sys.exit(1)
		try:
			self.status.update("[bold white]Waiting...")
			console.print ("[Status] Find Computers?", style = "status")
			input("")
			EnumerateAD.enumComputers(self)
		except KeyboardInterrupt:
			sys.exit(1)
			self.conn.unbind()
			console.print ("[Warning] Aborted", style = "warning")
			
	#Enumerate Active Directory Computers		
	def enumComputers(self):
		try:			
			self.status.update("[bold white]Finding Active Directory Computers...")
			sleep(1)
			#Search AD Computers
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(&(objectCategory=computer)(objectClass=computer))',
					 search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
			console.print ("[Success] Got all domain computers ", style = "success")
			console.print('Found {0} computers'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries)	
		except LDAPException as e:
			console.print ("[Warning] No Computers found", style = "warning")
			pprint ("Error {}".format(e))
			sys.exit(1)
		try:
			self.status.update("[bold white]Waiting...")
			console.print ("[Status] Find Groups?", style = "status")
			input("")
			EnumerateAD.enumerateGroups(self)
		except KeyboardInterrupt:
			sys.exit(1)
			self.conn.unbind()
			console.print ("[Warning] Aborted", style = "warning")
			
	#Enumerate Active Directory Groups			
	def enumerateGroups(self):
		self.status.update("[bold white]Finding Active Directory Groups...")
		sleep(1)
		try:
			#Search AD Group
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(groupType:1.2.840.113556.1.4.804:=2147483648)(member=*))',
					 search_scope=SUBTREE, attributes = 'member', size_limit=0)
			console.print ("[Success] Got all groups ", style = "success")
			console.print('Found {0} groups'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries)
		except LDAPException as e:
			console.print ("[Warning] No Groups found", style = "warning")
			pprint ("Error {}".format(e))
			sys.exit(1)
		try:
			self.status.update("[bold white]Waiting...")
			console.print ("[Status] Find Organisational Units?", style = "status")
			input("")
			EnumerateAD.enumerateOUs(self)
		except KeyboardInterrupt:
			sys.exit(1)
			self.conn.unbind()
			console.print ("[Warning] Aborted", style = "warning")
			
	#Enumerate Organisational Units
	def enumerateOUs(self):
		self.status.update("[bold white]Finding Organisational Units...")
		sleep(1)
		try:
			#Search AD Organisational Units
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(objectclass=organizationalUnit)',
					 search_scope=SUBTREE, attributes = 'member', size_limit=0)
			console.print ("[Success] Got all OUs ", style = "success")
			console.print('Found {0} OUs'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries)
		except LDAPException as e:
			console.print ("[Warning] No OUs found", style = "warning")
			pprint ("Error {}".format(e))
			sys.exit(1)
		try:
			self.status.update("[bold white]Waiting...")
			console.print ("[Status] Find ASREP Roastable Users?", style = "status")
			input("")
			EnumerateAD.enumKerbPreAuth(self)
		except KeyboardInterrupt:
			sys.exit(1)
			self.conn.unbind()
			console.print ("[Warning] Aborted", style = "warning")
	
	#Enumerate ASREP Roastable Users					
	def enumKerbPreAuth(self):
		self.status.update("[bold white]Finding Users that do not require Kerberos Pre-Authentication...")
		sleep(1)
		try:	
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(&(samaccounttype=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', 
					search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
			console.print('Found {0} accounts that does not require Kerberos preauthentication'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries)  
		except LDAPException as e:   
			console.print ("[Warning] No ASREP Roastable users found", style = "warning")
			pprint ("Error {}".format(e))
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
			console.print('Found {0} objects'.format(len(self.conn.entries)), style = "info")
			pprint(self.conn.entries)  
		except LDAPException as e:   
			console.print ("[Warning] Nothing found", style = "warning")
			pprint ("Error {}".format(e))
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
	parser.add_argument('-n', '--no_credentials', help='Run without credentials', action='store_true')
	parser.add_argument('-pw', '--password', type=str ,help='Password of the domain user')
	parser.add_argument('-h', '--help', help='show this help message and exit', action='help')
	parser.add_argument('-ip', '--ip_address', type=str, help='ip address of Active Directory')
	parser.add_argument('-e', '--enumObj', help='Enumerate Active Directory Objects', action='store_true')
	parser.add_argument('-c', '--connect', help='Just connect and nothing else', action='store_true')
	parser.add_argument('-v', '--verbose', action='store_true')
	parser.add_argument('-f', '--fuzz', action='store_true')
	args = parser.parse_args()
	
	#Display help page if no arguments are provided
	if len(sys.argv) < 2:
		console.print("[Warning] No Arguments Provided", style = "warning")
		parser.print_help()
		parser.exit(1)
		
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
		console.print("[Error] {} is not a valid domain name'".format(args.dc), style = "error")
		sys.exit(1)
	if not ipaddr:
		console.print("[Error] {} is not a valid IP Address'".format(args.ip_address), style = "error")
		sys.exit(1)
		
	titleArt()
	console.print("[Success] Lumberjack Started", style="success")	
	start_time = datetime.now()
	
	#Run main features
	try:
		enumAD = EnumerateAD(args.dc, args.ldaps, args.ldap, args.no_credentials, args.verbose, args.ip_address, args.connect, args.enumObj, args.fuzz, status, args.username, args.password)
		enumAD.connect()

		if args.enumObj is not False:
			enumAD.enumerateUsers()
		elif args.fuzz is not False:
			enumAD.searchRandom(args.fuzz)
		else:
			sys.exit(1)

	except RuntimeError as e:
		pprint ("Error {}".format(e))
	except KeyboardInterrupt:
		console.print ("[Warning] Aborting", style = "warning")
		
	status.update("[bold white]Exiting Lumberjack...")
	sleep(2)
	elapsed = datetime.now() - start_time
	console.print(f"Completed after {elapsed.total_seconds():.2f} seconds", style="warning")
	
	#print blank line
	pprint('')
	
if __name__ == "__main__":
	with console.status("[bold white]Starting Lumberjack...") as status:
		try:
			sleep(2)
			main()
			console.print("[Success] Finished", style="success")	
		except KeyboardInterrupt:
			console.print ("[Warning] Aborted", style= "warning")
