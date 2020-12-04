# ecartebleue CLI for VISA e-Carte Bleue

ecartebleue is an **unofficial** command line tool for the VISA e-Carte Bleue service. It generates a single-use card e-number linked to your VISA card.

***WARNING*** As it generates real e-number card, it is strongly recommended to read and understand the source code before using it. ***THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND***

## Features

- generate e-number card in EUR only
- choice of expiration duration
- authentication with gopass, manage several e-Carte Bleue accounts

next features will include 3D Secure verification, currencies choices, list of generated e-number card...

## Installation

**Python**

Test with Python 3.6

Python libraries to install
- requests: `pip3 install requests`
- lxml: `pip3 install lxml`

**gopass**

[gopass](https://www.gopass.pw/) is a simple but powerful password manager for your terminal. ecartebleue uses gopass to provide your login and password to the VISA e-Carte Bleue service.

**Configuration**

Configuration has to be done in the ecard.py file.
- Set your bank's name
- Set your gopass locations

You may add the script to your $PATH and rename the file to ecard (without extension). 


## Usage
```
usage: ecard [-h] [-c CARD] [-e] [-v] [-V] amount

positional arguments:
  amount                amount in euro

optional arguments:
  -h, --help            show this help message and exit
  -c CARD, --card CARD  cards name defined in gopass
  -e, --expire-in       expiration time in months, default is 3
                        allowed values are 3, 6, 9, 12, 15, 18, 21, 24
  -v, --verbose         verbose mode
  -V, --version         display version and quit
```
Example
```
# ecard 123.45
Card number : 1234567890123456
Expired at  : 01/23
CVV         : 123
Owner       : M XXXXX YYYYY
```