# ecartebleue CLI for VISA e-Carte Bleue

ecartebleue is an **unofficial** command line tool for the VISA e-Carte Bleue service. It generates a single-use card e-number linked to your VISA card.

***WARNING*** As it generates real e-number card, it is strongly recommended to read and understand the source code before using it. ***THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND***

## Features

- generate e-number card in EUR only
- choice of expiration duration
- 3D Secure authentication (only by SMS)
- list e-number cards history
- authentication with gopass, manage several e-Carte Bleue accounts

Next features will include 3DS authentication by mobile application, currencies choices, different way than gopass to provide authentication.

## Installation

**Python**

Tested with Python 3.6

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
  -l, --list            list historic of generated e-Carte Bleue
  -v, --verbose         verbose mode
  -V, --version         display version and quit
```
### Examples
Generate e-carte number:
```
# ecard 123.45

Card number : 1234567890123456
Expired at  : 01/23
CVV         : 123
Owner       : M XXXXX YYYYY

```
Generate e-carte number with 3D Secure authentication:
```
# ecard 123.45
3D Secure authentication required. Loading...
Authentication by SMS
Enter code: 12345678

Card number : 1234567890123456
Expired at  : 01/23
CVV         : 123
Owner       : M XXXXX YYYYY

```
List e-number cards history:
```
# ecard -l
╭────────────┬──────────────────┬─────────────────────┬───────────┬─────────────╮
│    DATE    │       COMMERCANT │       E-NUMERO      │   PLAFOND │ TRANSACTION │ 
├────────────┼──────────────────┼─────────────────────┼───────────┼─────────────┤
│ 08/12/2020 │            ESHOP │ 1234 5678 9012 0006 │  204,26 € │    204,26 € │ 
│ 06/12/2020 │                ─ │ 1234 5678 9012 0005 │   46,87 € │           ─ │ 
│ 05/12/2020 │     ANOTHER SHOP │ 1234 5678 9012 0002 │  370,50 € │   -120,32 € │ 
│ 05/12/2020 │           A SHOP │ 1234 5678 9012 0004 │   57,90 € │     42,00 € │ 
│ 29/11/2020 │ WONDERFUL SHOP 8 │ 1234 5678 9012 0003 │   51,50 € │     51,50 € │ 
│ 27/11/2020 │     ANOTHER SHOP │ 1234 5678 9012 0002 │  370,50 € │    370,50 € │ 
│ 25/11/2020 │        TINY SHOP │ 1234 5678 9012 0001 │ 1012,00 € │   1012,00 € │ 
│ 24/11/2020 │  FOREIGN SHOP CO │ 1234 5678 9012 0000 │   99,74 € │     99,74 € │ 
╰────────────┴──────────────────┴─────────────────────┴───────────┴─────────────╯
```