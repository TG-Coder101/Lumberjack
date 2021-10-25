##! /usr/bin/python3

#MIT License

#Copyright (c) 2021 Tom Gardner

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

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



