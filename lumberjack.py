#!/usr/bin/python3
# -*- coding: utf-8 -*-

try:
    #module imports
    import argparse
    import os
    import re
    import sys 
    import textwrap
    import datetime

    #other imports
    import ldap3
    from pprint import pprint
    from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, SUBTREE, NTLM, BASE, ALL_ATTRIBUTES, Entry, Attribute
    from ldap3.core.exceptions import LDAPBindError, LDAPException
    from time import sleep
    from rich.console import Console 
    from rich.console import Theme
    
    print ("Modules imported")
except Exception as e:
    print ("Error {}".format(e))

"""
lumberjack.py
"""

__version__ = "0.0.1"

custom_theme = Theme({"success": "blue", "error": "red", "warning": "yellow"})
console = Console(theme=custom_theme)
LDAP_BASE_DN = 'OU=Test Accounts,OU=User Accounts,OU=Accounts,DC=hacklab,DC=local'
SEARCH_FILTER = '(objectCategory=person)'    
#SEARCH_FILTER = '(uidNumber=500)' (objectclass=computer)
class EnumerateAD:

    def __init__(self, domainController, port, ldaps, ldap, no_credentials, verbose, username=None, password=None):
        self.dc = domainController
        self.dUser = username
        self.ldaps = ldaps
        self.ldap = ldap
        self.dPassword = password
        self.port = port
        self.noCreds = no_credentials
        self.verbose = verbose

    #Connect to domain
    def connect(self):
            
        try:   
            with console.status("[bold blue]Connecting to Active Directory...") as status: 
                #Connect through LDAP (Secure)
                if self.ldaps:    
                    self.server = Server(self.dc, self.port, use_ssl=True, get_info=ALL)
                    self.conn = Connection(self.server, self.dUser, self.dPassword, auto_bind=True, fast_decoder=True)
                    self.conn.bind()
                    self.conn.start_tls()
                    sleep(1)
                    console.print("Connected to Active Directory through LDAPS", style = "success")
                #Connect through LDAP
                elif self.ldap:
                    self.server = Server(self.dc, get_info=ALL)
                    self.conn = Connection(self.server, auto_bind=True, fast_decoder=True)
                    self.conn.bind()
                    sleep(1)
                    console.print("Connected to Active Directory through LDAP", style = "success")
                else :
                    sleep(1)
                    console.print ("[Error] Failed to connect", style = "error")
                    raise LDAPBindError
        except Exception as e:
            console.print ("[Error] Failed to connect{}".format(e), style = "error")
            raise LDAPBindError

    def enumerateUsers(self):
            with console.status("[bold blue]Finding Active Directory Users...") as status:
                try: 
                    #Search AD
                    self.conn.search(search_base=LDAP_BASE_DN, search_filter=SEARCH_FILTER, search_scope=SUBTREE, attributes = ALL_ATTRIBUTES, size_limit=0)
                    console.print("All users found", style = "success")
                    pprint(self.conn.entries)
                    pprint(self.conn.response)
                    sleep(1)
                    #Unbind connection to AD
                    self.conn.unbind()
                except LDAPException as e:
                    console.print ("[Warning] No Users found", style = "warning")
                    pprint ("Error {}".format(e))
                    sys.exit(1)

def arguments():

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
    required = parser.add_argument_group('Required Arguments')
    required.add_argument('dc', '--domain', type=str, help='Hostname of the Domain Controller')
    required.add_argument('-ls', '--ldaps', help='Connect to domain through LDAPS', action='store_true')
    required.add_argument('-u', '--username', type=str, help='Username of the domain user you want to query. The username format has to be `user@domain.org`')
    required.add_argument('--a', '--all', help='Run all checks', action='store_true')
    required.add_argument('--n', '--no-credentials', help='Run without credentials', action='store_true')
    required.add_argument('--pw', '--password', type=str ,help='Password of the domain user')
    required.add_argument('--p', '--port', help='Add port', action='store_true')
    required.add_argument('--No-Creds', '--No-Credentials', help='Connect without credentials', action='store_true')
    required.add_argument('--l', '--ldap', help='Connect to Active Directory through LDAP', action='store_true')
    
    #Optional arguments
    optional = parser.add_argument_group('Optional Arguments')
    optional.add_argument('--V', '--verbose', action='store_true')
    optional.add_argument('--h', '--help', help='show this help message and exit', action='help')

    args = required.parse_args() & optional.parse_args()

    # If theres more than 4 sub'ed (test.test.domain.local) or invalid username format
    domainRE = re.compile(r'^((?:[a-zA-Z0-9-.]+)?(?:[a-zA-Z0-9-.]+)?[a-zA-Z0-9-]+\.[a-zA-Z]+)$')
    userRE = re.compile(r'^([a-zA-Z0-9-\.]+@(?:[a-zA-Z0-9-.]+)?(?:[a-zA-Z0-9-.]+)?[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)$')

    domainMatch = domainRE.findall(args.dc)
    userMatch = userRE.findall(args.user)

    #if invalid domain name and username format
    if not domainMatch:
        console.print("[Error] Domain flag has to be in the format 'hacklab.local'")
        sys.exit(1)
    elif args.no_credentials:
        args.username = False
    elif not userMatch:
            console.print("[Error] User flag has to be in the form 'user@domain.local'", style = "error")
            sys.exit(1)  
    elif not vars(args):
        parser.pprint_help()
        parser.exit(1)
    else:
        sys.exit(1) 

def main():

    try:
        args = arguments()
    except Exception as e:
        pprint ("Error {}".format(e))
    start_time = datetime.now()
    try:
        enumerateAD = EnumerateAD(args)
        enumerateAD.run()
    except RuntimeError as e:
        pprint ("Error {}".format(e))
    except KeyboardInterrupt:
        console.print ("[Warning] Aborting", style = "warning")

    elapsed = datetime.now() - start_time
    pprint(f"\nCompleted after {elapsed.total_seconds():.2f} seconds")   
    
        
    print('')

if __name__ == "__main__":
    console.status("[bold blue]Starting...")
    sleep(1)
    main()



"""

    enumerateAD = EnumerateAD(args.dc, args.port, args.ldaps, args.ldap, args.no_credentials, args.verbose, args.username, args.password)


    if sys.argv:
        enumerateAD.run() 

def ldap_connection_no_credentials():
    server = ldap_server()
    return Connection(server, auto_bind=True, fast_decoder=True)

def ldap_server():
    return Server(args.server, use_ssl=True, tls=tls_configuration, get_info=ALL)

def get_dn(username):
    return "CN={0},OU=Test Accounts,OU=User Accounts," \
           "OU=Accounts,DC=test,DC=core,DC=bogus,DC=org,DC=uk".format(username)

def get_attributes(username, forename, surname):
    return {
        "displayName": username,
        "sAMAccountName": username,
        "userPrincipalName": "{0}@test.core.bogus.org.uk".format(username),
        "name": username,
        "givenName": forename,
        "sn": surname
    }

def get_groups():
    postfix = ',OU=MyService,OU=My Groups,DC=test,DC=core,DC=bogus,DC=org,DC=uk'
    return [
         ('CN=ROLE_A%s' % postfix)
    ]
def main():
    credentials = input("Do you have user credentials? Yes or No?:")
    if credentials == 'yes':
        ldap_connection()
        print(r   
                    Options: 
                    Get Users
                    Get Groups
                    Get Attributes
                    Get Domain    
         )
        selection = input("What information do you want?:")
        if selection == 'Get Users':
            find_ad_users()
        elif selection == 'Get Groups':
            get_groups()
        elif selection == 'Get Attributes':
            get_attributes()
        elif selection == 'Get Domain':
            get_dn()
             
    elif credentials == 'no':
        ldap_connection()
        ldap_connection_no_credentials()

if __name__ == "__main__":
    titleArt()
    parse_args()
    main()

"""
