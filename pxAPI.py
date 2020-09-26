import requests
import json
import time

class httpRequestType:
	get='GET'
	post='POST'

class pxAPI:
	def __init__(self,pxGridNode,clientName,clientCertFile,clientKeyFile,rootCAFile):
		self.pxGridNode=pxGridNode
		self.clientName=clientName
		self.clientCertFile=clientCertFile
		self.clientKeyFile=clientKeyFile
		self.rootCAFile=rootCAFile

	def sendHTTPRequest(self,requestType,url,username,password,headers={},data={}):
		if requestType==httpRequestType.get:
			response=requests.get(url,	headers=headers,
										auth=(username,password),
										cert=(self.clientCertFile,self.clientKeyFile),
										verify=self.rootCAFile)
			return(response)
		if requestType==httpRequestType.post:
			response=requests.post(url, data=json.dumps(data),
										headers=headers,
										auth=(username,password),
										cert=(self.clientCertFile,self.clientKeyFile),
										verify=self.rootCAFile)
			return(response)
		raise Exception("sendHTTPRequest: Unknown Request Type {}".format(requestType))
	
	def sendpxGridRequest(self,service,data={}):
		url="https://{}:8910/pxgrid/control/{}".format(self.pxGridNode,service)
		headers={'Content-Type':'application/json','Accept':'application/json'}
		response=self.sendHTTPRequest(httpRequestType.post,url,None,None,headers,data)
		if response.status_code==200:
			return(json.loads(response.text))
		raise Exception("Request {} failed with code {}".format(service,response.status_code))
	
	def accountActivate(self,activationWait=False):
		while True:
			accountState=self.sendpxGridRequest('AccountActivate',{'description':self.clientName})
			if not activationWait or accountState['accountState']=='ENABLED':
				return(accountState['accountState']=='ENABLED')
			time.sleep(60)
	
	def serviceLookup(self,serviceName):
		return(self.sendpxGridRequest('ServiceLookup',{'name':serviceName}))

	def serviceRegister(self,serviceName,serviceProperties):
		return(self.sendpxGridRequest('ServiceRegister',{'name':serviceName,'properties':serviceProperties}))

	def getAccessSecret(self,peerNodeName):
		return(self.sendpxGridRequest('AccessSecret',{'peerNodeName':peerNodeName}))
