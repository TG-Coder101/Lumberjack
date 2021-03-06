# Lumberjack
A python project for my honours dissertation

![image](https://user-images.githubusercontent.com/58516757/166745742-ac2ed9bb-04e7-42df-a46e-8079898a39da.png)

## Description
This is a prototype tool that uses python to identify and exploit vulnerabilities in an Active Directory, then generate reports on the vulnerabilities. This script makes use of Impacket by SecuraAuthPort and the Zerologon exploit developed by Secura

## Getting Started

### Dependencies
* Python 3.6 or higher
* See requirements.txt for additional dependencies

### Installation
Run this command after downloading this repository with git clone
```
pip3 install -r requirements.txt
```

### Executing program
Run this command to view help page
```
python3 lumberjack.py -h
```

![image](https://user-images.githubusercontent.com/58516757/166748501-9ce29baf-1379-4828-b134-39fa86380367.png)

![image](https://user-images.githubusercontent.com/58516757/166748552-c74f18a8-f0e8-4cd6-be12-9446bdb500cf.png)

Warning: Do not use in a production environment as some of the exploits in the script can cause serious damage to a domain. 

## Features
* Active Directory Enumeration
* Kerberoasting
* AS-REP Roasting
* CVE-2020-1472 (Zerologon)
* Automated Reporting

## Acknowledgments
* SecureAuthCorp
* Secura
* CasperGN
