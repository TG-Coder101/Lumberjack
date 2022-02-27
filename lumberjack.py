#!/usr/bin/python3
# -*- coding: utf-8 -*-
try:
	#module imports
    	import argparse
    	import os
    	import re
    	import sys
    	import textwrap
    	import ldap3
    	import datetime
	
    	#other imports
    	from datetime import datetime
    	from pprint import pprint
    	from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, SUBTREE, NTLM, BASE, ALL_ATTRIBUTES, Entry, Attribute
    	from ldap3.core.exceptions import LDAPBindError, LDAPException
    	from time import sleep
    	from rich.console import Console
    	from rich.console import Theme
except Exception as e:
    	print ("Error {}".format(e))

"""
lumberjack.py
"""
custom_theme = Theme({"success": "blue", "error": "red", "warning": "yellow"})
console = Console(theme=custom_theme)
LDAP_BASE_DN = 'OU=Test Accounts,OU=User Accounts,OU=Accounts,DC=hacklab,DC=local'
SEARCH_FILTER = '(objectCategory=person)'
#SEARCH_FILTER = '(uidNumber=500)' (objectclass=computer)
USER_NAME = 'CN=Administrator, CN=Users, DC=hacklabtest, DC=local'

class EnumerateAD:

	def __init__(self, domainController, port, ldaps, ldap, no_credentials, status, username, password):
		self.dc = domainController
		self.dUser = username
		self.ldaps = ldaps
		self.ldap = ldap
		self.dPassword = password
		self.port = port
		self.noCreds = no_credentials
		self.status = status

	#Connect to domain
	def connect(self):
		try:
			self.status.update(status="[bold blue]Connecting to Active Directory...")
			#Connect through LDAPS (Secure)
			if self.ldaps:
				self.server = Server('ldaps://{}'.format(self.dc), self.port, use_ssl=True, get_info=ALL)
				self.conn = Connection(self.server, USER_NAME, password = self.dPassword, auto_bind=True, auto_referrals = False, fast_decoder=True)
				self.conn.bind()
				self.conn.start_tls()
				sleep(1)
				console.print("+[Connected to Active Directory through LDAPS]+", style = "success")
			#Connect through LDAP
			elif self.ldap:
				self.server = Server('ldap://{}'.format(self.dc), get_info=ALL)
				self.conn = Connection(self.server, auto_bind=True, auto_referrals = False, fast_decoder=True)
				self.conn.bind()
				sleep(1)
				console.print("+[Connected to Active Directory through LDAP]+", style = "success")
			#Connect through LDAPS without Credentials
			elif self.no_Creds & self.ldaps:
				self.dUser = " "
				self.dPassword = " "
				self.server = Server('ldaps://{}'.format(self.dc), self.port, use_ssl=True, get_info=ALL)
				self.conn = Connection(self.server, user = self.dUser, password = self.dPassword, auto_bind=True, auto_referrals = False, fast_decoder=True)
				self.conn.bind()
				self.conn.start_tls()
				sleep(1)
				console.print("+[Connected to Active Directory through LDAPS and without credentials]+", style = "success")
			#Connect through LDAP without Credentials
			elif self.no_Creds & self.ldap:
				self.dUser = " "
				self.dPassword = " "
				self.server = Server('ldap://{}'.format(self.dc), get_info=ALL)
				self.conn = Connection(self.server, auto_bind=True, auto_referrals = False, fast_decoder=True)
				self.conn.bind()
				sleep(1)
				console.print("+[Connected to Active Directory through LDAP and without credentials]+", style = "success")                    			
			else :
				sleep(1)
				console.print ("[Error] Failed to connect: ", style = "error")
				raise LDAPBindError
				
		except Exception as e:
			console.print ("[Error] Failed to connect: {} ".format(e), style = "error")
			raise LDAPBindError

	def enumerateUsers(self):
		self.status.update("[bold blue]Finding Active Directory Users...")
		try:
			#Search AD
			self.conn.search(search_base=LDAP_BASE_DN, search_filter=SEARCH_FILTER, search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
			console.print("+[All users found]+", style = "success")
			pprint(self.conn.entries)
			pprint(self.conn.response)
			sleep(1)
			#Unbind connection to AD
			self.conn.unbind()
		except LDAPException as e:
			console.print ("[Warning] No Users found", style = "warning")
			pprint ("Error {}".format(e))
			sys.exit(1)

def main():

	parser = argparse.ArgumentParser(prog='Lumberjack', add_help=False, formatter_class=argparse.RawDescriptionHelpFormatter, description=textwrap.dedent('''
	            __                    __              _            __
	           / /   __  ______ ___  / /_  ___  _____(_)___ ______/ /__
	          / /   / / / / __ `__ \/ __ \/ _ \/ ___/ / __ `/ ___/ //_/
	         / /___/ /_/ / / / / / / /_/ /  __/ /  / / /_/ / /__/  ,<
	        /_____/\__,_/_/ /_/ /_/_.___/\___/_/__/ /\__,_/\___/_/|_|
	                                           /___/
	                  __.                                   	By Tom Gardner
	         ________/o |)
	        {_______{_rs|

       A Prototype Active Directory Vulnerability Identification, Exploitation, & Reporting Tool
    |*------------------------------------------------------------------------------------------*|
    '''))

	#Required arguments
	parser.add_argument('-dc', type=str, help='Hostname of the Domain Controller')
	parser.add_argument('-ls', '--ldaps', help='Connect to domain through LDAPS (Secure)', action='store_true')
	parser.add_argument('-l', '--ldap', help='Connect to domain through LDAP', action='store_true')
	parser.add_argument('-u', '--username', type=str, help='Username of the domain user you want to query. The username format has to be `user@domain.org`')
	parser.add_argument('-n', '--no_credentials', help='Run without credentials', action='store_true')
	parser.add_argument('-pw', '--password', type=str ,help='Password of the domain user')
	parser.add_argument('-p', '--port', type=int, help='Add port (Use 389 for ldap, 646 for ldaps)')
	parser.add_argument('-h', '--help', help='show this help message and exit', action='help')

	args = parser.parse_args()
	
	#Display help page if no arguments are provided
	if len(sys.argv) < 2:
		console.print("[Warning] No Arguments Provided", style = "warning")
		parser.print_help()
		parser.exit(1)
		
	# If theres more than 4 sub'ed (test.test.domain.local) or invalid username format
	domainRE = re.compile(r'^((?:[a-zA-Z0-9-.]+)?(?:[a-zA-Z0-9-.]+)?[a-zA-Z0-9-]+\.[a-zA-Z]+)$')
	userRE = re.compile(r'^([a-zA-Z0-9-\.]+@(?:[a-zA-Z0-9-.]+)?(?:[a-zA-Z0-9-.]+)?[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)$')

	domainMatch = domainRE.findall(args.dc)
	userMatch = userRE.findall(args.username)
	
	#if invalid domain name and username format
	if not domainMatch:
		console.print("[Error] Domain flag has to be in the format 'hacklab.local'", style = "error")
		sys.exit(1)
	elif args.no_credentials:
		args.username = False
	elif not userMatch:
	    	console.print("[Error] User flag has to be in the form 'user@domain.local'", style = "error")
	    	sys.exit(1)
	    	
	#The clock is running!
	start_time = datetime.now()
	try:
		enumerateAD = EnumerateAD(args.dc, args.port, args.ldaps, args.ldap, args.no_credentials, status, args.username, args.password)
		enumerateAD.connect()
		enumerateAD.enumerateUsers()
		
	except RuntimeError as e:
		pprint ("Error {}".format(e))
	except KeyboardInterrupt:
		console.print ("[Warning] Aborting", style = "warning")

	elapsed = datetime.now() - start_time
	pprint(f"\nCompleted after {elapsed.total_seconds():.2f} seconds")
	pprint('')
	
if __name__ == "__main__":
	with console.status("[bold blue]Starting...") as status:
		sleep(2)
		main()
	console.print("+[Finished]+", style="success")	
