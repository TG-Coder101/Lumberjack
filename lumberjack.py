##!/usr/bin/python3
# -*- coding: utf-8 -*-

try:
    #module imports
    import argparse
    import logging
    import os
    import subprocess
    import sys 

    #other imports
    import ldap3 
    import click
    import pypsrp  
    import ssl
    import pyfiglet
    from flask import json
    from termcolor import colored, cprint
    from pyfiglet import Figlet
    from pprint import pprint
    from ldap3 import Server, Connection, SUBTREE, ALL, LEVEL, ALL_ATTRIBUTES, Tls, MODIFY_REPLACE
    print ("Modules imported")
except Exception as e:
    print ("Error {}".format(e))

"""
lumberjack.py
"""
__version__ = "0.0.1"

OBJECT_CLASS = ['top', 'person', 'organizationalPerson', 'user']
LDAP_BASE_DN = 'OU=Test Accounts,OU=User Accounts,OU=Accounts,DC=test,DC=core,DC=bogus,DC=org,DC=UK'
search_filter = "(displayName={0}*)"
tls_configuration = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", help="server name", action="store_true")
    parser.add_argument("-u", "--user", help="username", action="store_true")
    parser.add_argument("-p", "--password", help="password", action="store_true")
    parser.add_argument("-P", "--port", help="port", action="store_true")
    return parser.parse_args()

args = parse_args()

def titleArt():

    f = Figlet(font="slant")
    cprint(colored(f.renderText('RPi Thermometer'), 'cyan'))

    print(r"""   __.                                                                                     
       ________/o |)                             By Tom Gardner
      {_______{_rs|  					
    
    An Active Directory vulnerability identification, exploitation, & reporting tool 

    """ )
    print ("    	Version ",__version__)

def find_ad_users(username):
    with ldap_connection() as c:
        c.search(search_base=LDAP_BASE_DN,
                 search_filter=search_filter.format(username),
                 search_scope=SUBTREE,
                 attributes=ALL_ATTRIBUTES,
                 get_operational_attributes=True)

    return json.loads(c.response_to_json())

def ldap_connection():
    server = ldap_server()
    return Connection(server, args.user, args.password, auto_bind=True, fast_decoder=True)

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
        print(r"""   
                    Options: 
                    Get Users
                    Get Groups
                    Get Attributes
                    Get Domain    
        """ )
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
