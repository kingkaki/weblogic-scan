# -*- coding: utf-8 -*-
# @Author: kingkk
# @Date:   2018-11-06 19:12:26
# @Last Modified by:   King kaki
# @Last Modified time: 2018-11-08 18:20:46

import config
from lib.display import *
from lib import prepare
import sys

if __name__ == '__main__':
	success(prepare.banner)
	if config.server == '':
		info("[!] plz input recv_server or fill in config.py:", end=" ")
		config.server = input()
	if len(sys.argv) == 1:
		prepare.mode1()
	elif len(sys.argv) == 2:
		prepare.mode2(sys.argv[1])
	else:
		info(prepare.helper.format(name=sys.argv[0]))














