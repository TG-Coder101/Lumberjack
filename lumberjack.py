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
    	import pyfiglet
	
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

custom_theme = Theme({"success": "cyan", "error": "red", "warning": "yellow", "status": "green"})
console = Console(theme=custom_theme)
LDAP_BASE_DN = 'DC=hacklabtest,DC=local'
USER_NAME = 'CN=Administrator, CN=Users, DC=hacklabtest, DC=local'

class EnumerateAD:

	def __init__(self, domainController, ldaps, ldap, no_credentials, verbose, ip_address, connect, enumObj, status, username, password):
		self.dc = domainController
		self.dUser = username
		self.ldaps = ldaps
		self.ldap = ldap
		self.dPassword = password
		self.noCreds = no_credentials
		self.dIP = ip_address
		self.status = status
		self.verbose = verbose
	
	#Connect to domain
	def connect(self):
		self.status.update(status="[bold white]Connecting to Active Directory...")
		try:
			#Connect through LDAPS (Secure)
			if self.ldaps:
				self.server_pool = ServerPool(self.dIP)
				self.server = Server(self.dc, port=646, use_ssl=True, get_info=ALL)
				self.server_pool.add(self.server)
				self.conn = Connection(self.server_pool, self.dUser, password=self.dPassword, auto_bind=True, auto_referrals = False, fast_decoder=True)
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
				self.conn = Connection(self.server_pool, user=self.dUser, password=self.dPassword, auto_bind=True, auto_referrals = False, fast_decoder=True)
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
			
	#Enumerate Active Directory Users		
	def enumerateUsers(self):
		try:			
			self.status.update("[bold white]Finding Active Directory Users...")
			#Search AD  Users (Verbose)
			if self.verbose:
				self.conn.search(search_base=LDAP_BASE_DN, search_filter='(objectCategory=person)', search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
				console.print ("[Success] Got all domain users ", style = "success")
				pprint(self.conn.entries)
			else:
				uAttributes = ['uid', 'sn', 'givenName', 'mail', 'uidNumber', 'sn', 'cn']
				self.conn.search(search_base=LDAP_BASE_DN, search_filter='(objectCategory=person)', search_scope=SUBTREE, attributes = uAttributes, size_limit=0)
				console.print ("[Success] Got all domain users ", style = "success")
				pprint(self.conn.entries)		
		except LDAPException as e:
			console.print ("[Warning] No Users found", style = "warning")
			pprint ("Error {}".format(e))
			sys.exit(1)
		try:
			self.status.update("[bold white]Waiting...")
			console.print ("[Status] Continue?", style = "status")
			input("")
			EnumerateAD.enumerateGroups(self)
		except KeyboardInterrupt:
			sys.exit(1)
			self.conn.unbind()
			console.print ("[Warning] Aborted", style = "warning")
				
	def enumerateGroups(self):
		self.status.update("[bold white]Finding Active Directory Groups...")
		sleep(2)
		try:
			#Search AD  Group
			self.conn.search(search_base=LDAP_BASE_DN, search_filter='(objectCategory=group)', search_scope=SUBTREE, attributes = 'member', size_limit=0)
			console.print ("[Success] Got all groups ", style = "success")
			pprint(self.conn.entries)
			self.conn.unbind()
			console.print("[Success] Finished", style="success")	
			sys.exit(1)
		except LDAPException as e:
			console.print ("[Warning] No Groups found", style = "warning")
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
	parser.add_argument('-u', '--username', type=str, help='Username of domain user. The username format must be `user@domain.org`')
	parser.add_argument('-n', '--no_credentials', help='Run without credentials', action='store_true')
	parser.add_argument('-pw', '--password', type=str ,help='Password of the domain user')
	parser.add_argument('-h', '--help', help='show this help message and exit', action='help')
	parser.add_argument('-ip', '--ip_address', type=str, help='ip address of Active Directory')
	parser.add_argument('-e', '--enumObj', help='Enumerate Active Directory Objects', action='store_true')
	parser.add_argument('-c', '--connect', help='Just connect and nothing else', action='store_true')
	parser.add_argument('-v', '--verbose', action='store_true')
	args = parser.parse_args()
	
	#Display help page if no arguments are provided
	if len(sys.argv) < 2:
		console.print("[Warning] No Arguments Provided", style = "warning")
		parser.print_help()
		parser.exit(1)
	if args.connect:
		args.enumObj = False
		
	# If theres more than 4 sub'ed (test.test.domain.local) or invalid username format
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
		enumAD = EnumerateAD(args.dc, args.ldaps, args.ldap, args.no_credentials, args.verbose, args.ip_address, args.connect, args.enumObj, status, args.username, args.password)
		enumAD.connect()
		if args.enumObj is not False:
			enumAD.enumerateUsers()
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
