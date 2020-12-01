import requests
import json
import time
import re
import ipaddress
import logging
import http.client as http_client
from dateutil import parser
import asyncio
import websockets
import ssl
import base64

class httpRequestType:
	get='GET'
	post='POST'

class pxGridServices:
	anc='com.cisco.ise.config.anc'
	session='com.cisco.ise.session'
	endpoint='com.cisco.endpoint.asset'
	mdm='com.cisco.ise.mdm'
	profiler='com.cisco.ise.config.profiler'
	radius='com.cisco.ise.radius'
	system='com.cisco.ise.system'
	trustsec='com.cisco.ise.trustsec'
	trustsecConfig='com.cisco.ise.config.trustsec'
	sxp='com.cisco.ise.sxp'

class stompFrame:
	def __init__(self,command,headers,data=''):
		self.command=command
		self.headers=headers
		self.data=data
	
	def getFrame(self):
		frame=self.command+'\n'
		for key in self.headers:
			frame=frame+key+':'+self.headers[key]+'\n'
		frame=frame+'\n'
		if self.data:
			frame=frame+self.data+'\n'
		frame=frame+'\x00'
		return(frame.encode('utf-8'))

	@staticmethod
	def parsePacket(packet):
		lines=packet.decode('utf-8').split('\n')
		command=lines[0]
		headers={}
		for lineNum in range (1,len(lines)-2):
			header=lines[lineNum].split(':')
			headers[header[0]]=header[1]
		data=lines[-1].replace('\x00','')
		return(stompFrame(command,headers,data))

class pxAPI:
	def __init__(self,pxGridNode,clientName,clientCertFile,clientKeyFile,rootCAFile=False):
		"""
		Initialize class
			pxGridNode: FQDN of pxGrid PSN
			clientName: Name that will show up in pxGrid clients list in ISE
			clientCertFile: File name containing client certificate
			clientKeyFile: File name containing private key. Encrypted key is not supported
			rootCAFile: File name containing root CA for pxGrid PSN certificate.
						If root CA is not specified, server certificate validation is disabled.
		"""
		self.pxGridNode=pxGridNode
		self.clientName=clientName
		self.clientCertFile=clientCertFile
		self.clientKeyFile=clientKeyFile
		if rootCAFile:
			self.rootCAFile=rootCAFile
		else:
			self.rootCAFile=False

	def __isValidIP(self,ipAddress):
		"""
		Check if IP Address is valid
		"""
		try:
			ipaddress.ip_address(ipAddress)
		except ValueError:
			return(False)
		return(True)
	
	def __isValidMac(self,macAddress):
		"""
		Check if MAC Address is valid
		"""
		return(re.search(r'^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$',macAddress,re.IGNORECASE))
	
	def __checkIP(self,ipAddress):
		"""
		Raise an exception if IP Address is not valid
		"""
		if not self.__isValidIP(ipAddress):
			raise Exception("Invalid IP Address: {}".format(ipAddress))
	
	def __checkMac(self,macAddress):
		"""
		Raise an exception if MAC Address is not valid
		"""
		if not self.__isValidMac(macAddress):
			raise Exception("Invalid MAC Address (must be HH:HH:HH:HH:HH:HH) {}".format(macAddress))

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
		response=self.sendHTTPRequest(httpRequestType.post,url,self.clientName,None,headers,data)
		if response.status_code==200:
			return(json.loads(response.text))
		raise Exception("Request {} failed with code {}. Content: {}".format(service,response.status_code,response.text))
	
	def sendpxGridAPI(self,serviceName,apiName,data={}):
		serviceInfo=self.serviceLookup(serviceName)
		nodeName=serviceInfo['services'][0]['nodeName']
		restBaseUrl=serviceInfo['services'][0]['properties']['restBaseUrl']
		secret=self.getAccessSecret(nodeName)
		url="{}/{}".format(restBaseUrl,apiName)
		headers={'Content-Type':'application/json','Accept':'application/json'}
		response=self.sendHTTPRequest(httpRequestType.post,url,self.clientName,secret,headers,data)
		if response.status_code==200:
			try:
				return(json.loads(response.text))
			except:
				return({})
		if response.status_code==204:
			return({})
		raise Exception("API {} to service {} failed with code {}. Content: {}".format(apiName,serviceName,response.status_code,response.text))

	async def wsConnect(self,url,password):
		sslContext=ssl.create_default_context()
		sslContext.load_cert_chain(certfile=self.clientCertFile,keyfile=self.clientKeyFile)
		sslContext.load_verify_locations(cafile=self.rootCAFile)
		self.ws=await websockets.connect(uri=url,
										 extra_headers={'Authorization':'Basic '+base64.b64encode("{}:{}".format(self.clientName,password).encode()).decode()},
										 ssl=sslContext)
	
	async def stompConnect(self,hostName):
		"""
		Connect to pxGrid node
			hostname: FQDN of pxGrid node
		"""
		frame=stompFrame('CONNECT',{'accept-version':'1.2','host':hostName})
		await self.ws.send(frame.getFrame())

	async def stompDisconnect(self,receipt):
		"""
		Disconnect from service
			receipt: This string will echo back from service to confirm disconnect
		"""
		frame=stompFrame('DISCONNECT',{'receipt':receipt})
		await self.ws.send(frame.getFrame())
		await self.ws.close()

	async def stompSubscribe(self,topicName):
		"""
		Subscribe to topic
			topicName: name of topic
		"""
		frame=stompFrame('SUBSCRIBE',{'destination':topicName,'id':'pyAPI'})
		await self.ws.send(frame.getFrame())

	async def stompSend(self,topicName,data):
		"""
		Send stomp packet
			topicName: Name of topic
			data: Data to be sent
		"""
		frame=stompFrame('SEND',{'topic':topicName,'content-length':str(len(data))},data)
		await self.ws.send(frame.getFrame())
	
	async def stompRead(self):
		"""
		Receive and read stomp packet
			returns stompFrame object
		"""
		packet=await self.ws.recv()
		return(stompFrame.parsePacket(packet))
	
	async def topicSubscribe(self,serviceName,topicName):
		"""
		Subscribe to topic
			serviceName: Name of pxGrid service
			topicName: Name of topic to subscribe to
		"""
		serviceInfo=self.serviceLookup(serviceName)
		topic=serviceInfo['services'][0]['properties'][topicName]
		pubsubServiceInfo=self.serviceLookup(serviceInfo['services'][0]['properties']['wsPubsubService'])
		nodeName=pubsubServiceInfo['services'][0]['nodeName']
		wsUrl=pubsubServiceInfo['services'][0]['properties']['wsUrl']
		secret=self.getAccessSecret(nodeName)
		await self.wsConnect(wsUrl,secret)
		await self.stompConnect(nodeName)
		await self.stompSubscribe(topic)

	def accountActivate(self,activationWait=False):
		"""
		Activate pxGrid Account in ISE
			activationWait: if set to True, the API call will retry every 60 seconds until the request is approved in ISE

			Returns True if account is approved, otherwise False
		"""
		while True:
			accountState=self.sendpxGridRequest('AccountActivate',{})
			if not activationWait or accountState['accountState']=='ENABLED':
				return(accountState['accountState']=='ENABLED')
			time.sleep(60)
	
	def serviceLookup(self,serviceName):
		"""
		Looks up pxGrid service information
			serviceName: Name of pxGrid service
		"""
		return(self.sendpxGridRequest('ServiceLookup',{'name':serviceName}))

	def serviceRegister(self,serviceName,serviceProperties):
		"""
		Register pxGrid service
			serviceName: Name of new service
			serviceProperties: Service properties
		"""
		return(self.sendpxGridRequest('ServiceRegister',{'name':serviceName,'properties':serviceProperties}))

	def getAccessSecret(self,peerNodeName):
		"""
		Retrieve Access Secret to communicate to a pxGrid node
			peerNodeName: Name of the remote node
		"""
		return(self.sendpxGridRequest('AccessSecret',{'peerNodeName':peerNodeName})['secret'])
	
	def getSessions(self):
		"""
		Retrieve all active sessions
		"""
		return(self.sendpxGridAPI(pxGridServices.session,'getSessions'))
	
	def getSessionByIpAddress(self,ipAddress):
		"""
		Retrieve active session by IP Address
			ipAddress: Endpoint IP Address
		"""
		self.__checkIP(ipAddress)
		return(self.sendpxGridAPI(pxGridServices.session,'getSessionByIpAddress',{'ipAddress':ipAddress}))

	def getSessionByMacAddress(self,macAddress):
		"""
		Retrieve active session by MAC Address
			macAddress: Endpoint MAC Address
		"""
		self.__checkMac(macAddress)
		return(self.sendpxGridAPI(pxGridServices.session,'getSessionByMacAddress',{'macAddress':macAddress}))

	def getUserGroups(self):
		"""
		Retrieve all user to group assignments
		"""
		return(self.sendpxGridAPI(pxGridServices.session,'getUserGroups'))

	def getUserGroupByUserName(self,userName):
		"""
		Retries group assignment for a specific user
			userName: Username of the user
		"""
		return(self.sendpxGridAPI(pxGridServices.session,'getUserGroupByUserName',{'userName':userName}))
	
	def ancGetPolicies(self):
		"""
		Retrieve all ANC Policies
		"""
		return(self.sendpxGridAPI(pxGridServices.anc,'getPolicies'))

	def ancGetPolicyByName(self,name):
		"""
		Retrieve ANC Policy by name
			name: Name of ANC Policy
		"""
		return(self.sendpxGridAPI(pxGridServices.anc,'getPolicyByName',{'name':name}))
	
	def ancCreatePolicy(self,name,actions):
		"""
		Create ANC Policy
			name: Name of ANC Policy
			actions: Action that ISE will perform and ANC policy is assigned.
					 Valid options: QUARANTINE, SHUT_DOWN or PORT_BOUNCE
		"""
		if not actions in ['QUARANTINE','SHUT_DOWN','PORT_BOUNCE']:
			raise Exception("Invalid action {}. Valid options: QUARANTINE, SHUT_DOWN or PORT_BOUNCE".format(actions))
		return(self.sendpxGridAPI(pxGridServices.anc,'createPolicy',{'name':name,'actions':[actions]}))
		
	def ancDeletePolicyByName(self,name):
		"""
		Delete ANC Policy
			name: Name of ANC Policy
		"""
		return(self.sendpxGridAPI(pxGridServices.anc,'deletePolicyByName',{'name':name}))

	def ancGetEndponts(self):
		"""
		Retrive all endpoints assigned to ANC Policies
		"""
		return(self.sendpxGridAPI(pxGridServices.anc,'getEndpoints'))

	def ancGetEndpontByMacAddress(self,macAddress):
		"""
		Retrieve ANC Policy assignment by MAC Address
			macAddress: MAC Address of the endpoint
		"""
		self.__checkMac(macAddress)
		return(self.sendpxGridAPI(pxGridServices.anc,'getEndpointByMacAddress',{'macAddress':macAddress}))
	
	
	def ancGetEndpointPolicies(self):
		"""
		Retrieves endpoint to ANC Policy assignments based on MAC Address and NAS-IP-Address. This feature was added in 2.6P7
		"""
		return(self.sendpxGridAPI(pxGridServices.anc,'getEndpointPolicies'))
	
	def ancGetEndpointByNasIpAddress(self,macAddress,nasIpAddress):
		"""
		Retrieves endpoint to ANC Policy assignments based on MAC Address and NAS-IP-Address. This feature was added in 2.6P7
			macAddress: Endpoint MAC Address
			nasIpAddress: Device IP Address
		"""
		self.__checkMac(macAddress)
		self.__checkIP(nasIpAddress)
		return(self.sendpxGridAPI(pxGridServices.anc,'getEndpointByNasIpAddress',{'macAddress':macAddress,'nasIpAddress':nasIpAddress}))

	def ancApplyEndpointByMacAddress(self,policyName,macAddress):
		"""
		Apply ANC Policy by MAC Address. Endpoint does not need to be online.
			policyName: Name of ANC Policy
			macAddress: MAC Address of endpoint
		"""
		self.__checkMac(macAddress)
		return(self.sendpxGridAPI(pxGridServices.anc,'applyEndpointByMacAddress',{'policyName':policyName,'macAddress':macAddress}))

	def ancApplyEndpointByIpAddress(self,policyName,ipAddress):
		"""
		Apply ANC Policy by IP Address. Requires that the endpoint is connected to the network
			policyName: Name of ANC Policy
			ipAddress: IP Address of endpoint
		"""
		self.__checkIP(ipAddress)
		return(self.sendpxGridAPI(pxGridServices.anc,'applyEndpointByIpAddress',{'policyName':policyName,'ipAddress':ipAddress}))

	def ancApplyEndpointPolicy(self,policyName,macAddress,nasIpAddress):
		"""
		Apply ANC Policy by MAC Address and NAS-IP-Address. Endpoint does not need to be connected to the network. This feature was added in 2.6P7
			policyName: Name of ANC Policy
			macAddress: MAC Address of endpoint
			nasIpAddress: Device IP Address
		"""
		self.__checkMac(macAddress)
		self.__checkIP(nasIpAddress)
		return(self.sendpxGridAPI(pxGridServices.anc,'applyEndpointPolicy',{'policyName':policyName,'macAddress':macAddress,'nasIpAddress':nasIpAddress}))

	def ancClearEndpointByMacAddress(self,macAddress):
		"""
		Clear ANC Policy from endpoint by MAC Address
			macAddress: MAC Address of endpoint
		"""
		self.__checkMac(macAddress)
		return(self.sendpxGridAPI(pxGridServices.anc,'clearEndpointByMacAddress',{'macAddress':macAddress}))
	
	def ancClearEndpointPolicy(self,macAddress,nasIpAddress):
		"""
		Clear ANC Policy from endpoint by MAC Address and NAS-IP-Address. This feature was added in 2.6P7
		"""
		self.__checkMac(macAddress)
		self.__checkIP(nasIpAddress)
		return(self.sendpxGridAPI(pxGridServices.anc,'clearEndpointPolicy',{'macAddress':macAddress,'nasIpAddress':nasIpAddress}))

	def ancGetOperationStatus(self,operationId):
		"""
		Get status of an ongoing ANC operation
			operationId: Operation ID to look up
		"""
		return(self.sendpxGridAPI(pxGridServices.anc,'getOperationStatus',{'operationId':operationId}))

	def mdmGetEndpoints(self):
		"""
		Retrieve all MDM endpoints and their MDM attributes
		"""
		return(self.sendpxGridAPI(pxGridServices.mdm,'getEndpoints'))
	
	def mdmGetEndpointByMacAddress(self,macAddress):
		"""
		Retrieve MDM status of an endpoint based on MAC Address
			macAddress: MAC Address of endpoint
		"""
		self.__checkMac(macAddress)
		return(self.sendpxGridAPI(pxGridServices.mdm,'getEndpointByMacAddress',{'macAddress':macAddress}))
	
	def mdmGetEndpointsByType(self,mdmType):
		"""
		Retrive MDM endpoints by type
			mdmType: Valid options are NON_COMPLIANT, REGISTERED or DISCONNECTED
		"""
		if not mdmType in ['NON_COMPLIANT','REGISTERED','DISCONNECTED']:
			raise Exception("Invalid type {}. Valid options: NON_COMPLIANT, REGISTERED or DISCONNECTED".format(mdmType))
		return(self.sendpxGridAPI(pxGridServices.mdm,'getEndpointsByType',{'type':mdmType}))
	
	def mdmGetEndpointsByOsType(self,osType):
		"""
		Retrive MDM endpoints by OS type
			osType: Valid options are ANDROID, IOS or WINDOWS
		"""
		if not osType in ['ANDROID','IOS','WINDOWS']:
			raise Exception("Invalid OS type {}. Valid options: ANDROID, IOS or WINDOWS".format(osType))
		return(self.sendpxGridAPI(pxGridServices.mdm,'getEndpointsByOsType',{'osType':osType}))

	def profilerGetProfiles(self):
		"""
		Retrive all profiles
		"""
		return(self.sendpxGridAPI(pxGridServices.profiler,'getProfiles'))

	def radiusGetFailures(self,startTimestamp=None):
		"""
		Retrieve RADIUS failure statistics
			startTimestamp: Optionally specify a longer time range. By default, last 1 hour of statistics is retrieved.
		"""
		data={}
		if startTimestamp:
			data['startTimestamp']=parser.parse(startTimestamp).astimezone().isoformat()
		return(self.sendpxGridAPI(pxGridServices.radius,'getFailures',data))

	def radiusGetFailureById(self,id):
		"""
		Retrieve RADIUS failures by ID
			id: RADIUS code to retrieve
		"""
		return(self.sendpxGridAPI(pxGridServices.radius,'getFailureById',{'id':id}))

	def systemGetHealths(self,nodeName=None,startTimestamp=None):
		"""
		Retrieve system health statistics
			nodeName: Optionally filter by a specific ISE node
			startTimestamp: Optionally specify a longer time range. By default, last 1 hour of statistics is retrieved.
		"""
		data={}
		if nodeName:
			data['nodeName']=nodeName
		if startTimestamp:
			data['startTimestamp']=parser.parse(startTimestamp).astimezone().isoformat()
		return(self.sendpxGridAPI(pxGridServices.system,'getHealths',data))

	def systemGetPerformances(self,nodeName=None,startTimestamp=None):
		"""
		Retrieve system performance statistics
			nodeName: Optionally filter by a specific ISE node
			startTimestamp: Optionally specify a longer time range. By default, last 1 hour of statistics is retrieved.
		"""
		data={}
		if nodeName:
			data['nodeName']=nodeName
		if startTimestamp:
			data['startTimestamp']=parser.parse(startTimestamp).astimezone().isoformat()
		return(self.sendpxGridAPI(pxGridServices.system,'getPerformances',data))

	def trustsecGetSecurityGroups(self,id=None):
		"""
		Retrieve Trustsec SGTs
			id: Optionally filter by ID
		"""
		data={}
		if id:
			data['id']=id
		return(self.sendpxGridAPI(pxGridServices.trustsecConfig,'getSecurityGroups',data))

	def trustsecGetSecurityGroupAcls(self,id=None):
		"""
		Retrieve Trustsec ACLs
			id: Optionally filter by ID
		"""
		data={}
		if id:
			data['id']=id
		return(self.sendpxGridAPI(pxGridServices.trustsecConfig,'getSecurityGroupAcls',data))

	def trustsecGetEgressPolicies(self):
		"""
		Retrive all Trustsec egress policies
		"""
		return(self.sendpxGridAPI(pxGridServices.trustsecConfig,'getEgressPolicies'))
	
	def trustsecGetEgressMatrices(self):
		"""
		Retrieve all Trustsec egress matrices
		"""
		return(self.sendpxGridAPI(pxGridServices.trustsecConfig,'getEgressMatrices'))

	def trustsecGetBindings(self):
		"""
		Retrieve all SXP bindings
		"""
		return(self.sendpxGridAPI(pxGridServices.sxp,'getBindings'))
