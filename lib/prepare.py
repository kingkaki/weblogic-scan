# -*- coding: utf-8 -*-
# @Author: kingkk
# @Date:   2018-11-08 15:09:07
# @Last Modified by:   kingkk
# @Last Modified time: 2018-11-08 16:28:18
import re
from urllib.parse import urlparse
from lib.display import *
from lib.vuln import *


banner = r"""               _     _             _                               
 __      _____| |__ | | ___   __ _(_) ___      ___  ___ __ _ _ __  
 \ \ /\ / / _ \ '_ \| |/ _ \ / _` | |/ __|____/ __|/ __/ _` | '_ \ 
  \ V  V /  __/ |_) | | (_) | (_| | | (_______\__ \ (__ (_| | | | |
   \_/\_/ \___|_.__/|_|\___/ \__, |_|\___|    |___/\___\__,_|_| |_|
                             |___/                                 
author:  kingkk
version: python3
expand:	 requests
github:  https://github.com/kingkaki/weblogic-scan
"""

helper = '''[!] wrong format
1: python {name}
   scan all url in url.txt
2: python {name} target
   scan only one target
   E.g: python {name} 127.0.0.1:7001'''

def url2target(url):
	if url.startswith('https'):
		target = urlparse(url).netloc
		if ':' not in target:
			target = target + ':443'
	elif url.startswith('http'):
		target = urlparse(url).netloc
		if ':' not in target:
			target = target + ':80'
	else:
		target = urlparse(url).path
		if ':' not in target:
			target = target + ':80'
	return target	

def mode1():
	# mode1 扫描字典中的所有url
	with open("url.txt","r") as f:
		targets = [url2target(target.strip()) for target in f.readlines()]
	for target in targets:
		try:
			uuid_SSRF(target)
			console(target)
			CVE_2017_10271(target)			
			CVE_2018_2628(target)
		except requests.exceptions.ConnectionError as e:
			info("[-] is busy: {}".format(target))
		except requests.exceptions.ReadTimeout as e:
			info("[-] time out: {}".format(target))
		except KeyboardInterrupt as e:
			warning("\033[31m[!] user aborted\033[0m")
			exit()

def mode2(url):
	# mode2 扫描单个url
	target = url2target(url.strip())
	try:
		uuid_SSRF(target)
		console(target)
		CVE_2017_10271(target)			
		CVE_2018_2628(target)
	except requests.exceptions.ConnectionError as e:
		info("[-] is busy: {}".format(target))
	except requests.exceptions.ReadTimeout as e:
		info("[-] time out: {}".format(target))
	except KeyboardInterrupt as e:
		warning("\033[31m[!] user aborted\033[0m")
		exit()




