##! /usr/bin/python3

"""
lumberjack.py
"""
__version__ = "0.0.1"

#module imports
import argparse
import logging

#other imports

def titleArt():

    print(r"""
        __                    __              _            __  
       / /   __  ______ ___  / /_  ___  _____(_)___  _____/ /__             
      / /   / / / / __ `__ \/ __ \/ _ \/ ___/ / __ `/ ___/ //_/
     / /___/ /_/ / / / / / / /_/ /  __/ /  / / /_/ / /__/  ,<   
    /_____/\__,_/_/ /_/ /_/_.___/\___/_/__/ /\__,_/\___/_/|_|  
                __.                    /___/                                                                 
       ________/o |)
      {_______{_rs|               

    An Active Directory vulnerability identification, exploitation, & reporting tool 
    """ )
    print ("    Version ",__version__)

titleArt()



