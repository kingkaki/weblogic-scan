# -*- coding: utf-8 -*-
# @Author: kingkk
# @Date:   2018-11-07 11:36:49
# @Last Modified by:   kingkk
# @Last Modified time: 2018-11-07 16:40:02
def warning(string, *args, **kwargs):
	print('\033[31m{}\033[31m'.format(string), *args, **kwargs)

def success(string, *args, **kwargs):
	print('\033[32m{}\033[32m'.format(string), *args, **kwargs)

def info(string, *args, **kwargs):
	print('\033[33m{}\033[33m'.format(string), *args, **kwargs)

def primary(string, *args, **kwargs):
	print('\033[34m{}\033[34m'.format(string), *args, **kwargs)