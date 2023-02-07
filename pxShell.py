#!/usr/bin/env python3
#
# Copyright (c) 2021 Cisco Systems, Inc. and/or its affiliates
#
from requests import JSONDecodeError
from pxAPI import pxAPI,stompFrame,pxGridServices
import cmd
import json
import logging
import asyncio
import ssl
import websocket
import http.client as http_client
import signal
import re
from asyncio.tasks import FIRST_COMPLETED
from websockets import ConnectionClosed
from base64 import b64encode

class pxShell(cmd.Cmd):
	intro='Welcome to pxShell.'
	prompt='pxShell> '
	config={'clientName':'','pxGridNode':'','clientCertFile':'','clientKeyFile':'','rootCAFile':'','password': ''}

	def onecmd(self,line):
		if line and not line.split()[0] in ['EOF','accountcreate','config','debug','help']:
			if self.config['clientName']=='':
				print('Client name is not defined. Use config show to verify.')
				return
			if self.config['pxGridNode']=='':
				print('pxGrid Node is not defined. Use config show to verify.')
				return
			if (self.config['clientCertFile']=='' or self.config['clientKeyFile']=='') and self.config['password']=='':
				print('Either client certificate/key or password is required. Use config show to verify.')
			if not hasattr(self,'api'):
				print('API is not initialized. Use config apply.')
				return
		try:
			return(cmd.Cmd.onecmd(self, line))
		except Exception as e:
			print("Error occured: {}".format(e))

	def printJSON(self,value):
		print(json.dumps(value,indent=2))

	async def futureReadMessage(self,api,future):
		try:
			frame = await api.stompRead()
			future.set_result(frame)
		except ConnectionClosed:
			print('Websocket connection closed')

	async def subscribeLoop(self,api,serviceName,topicName):
		await api.topicSubscribe(serviceName,topicName)
		print("Ctrl-C to disconnect...")
		while True:
			future = asyncio.Future()
			futureRead = self.futureReadMessage(api, future)
			try:
				await asyncio.wait([futureRead],return_when=FIRST_COMPLETED)
			except asyncio.CancelledError:
				await api.stompDisconnect('123')
				break
			else:
				frame = future.result()
				try:
					frameData=json.loads(frame.data)
				except json.decoder.JSONDecodeError:
					frameData={}
				print("Received Packet: command={} content:\n{}".format(frame.command,json.dumps(frameData,indent=2)))

	def topicSubscribe(self,serviceName,topicName):
		loop = asyncio.get_event_loop()
		subscribeTask = asyncio.ensure_future(self.subscribeLoop(self.api,serviceName,topicName))
		loop.add_signal_handler(signal.SIGINT,subscribeTask.cancel)
		loop.add_signal_handler(signal.SIGTERM,subscribeTask.cancel)
		loop.run_until_complete(subscribeTask)

	def printTopics(self,serviceName):
		serviceInfo=self.api.serviceLookup(serviceName)
		for serviceProperty in serviceInfo['services'][0]['properties']:
			if re.search(r'^.*Topic',serviceProperty,re.IGNORECASE):
				self.printJSON(serviceProperty)

	def emptyline(self):
		pass

	def do_session(self,line):
		"""session options:
		all: Retrive all active sessions
		byip <x.x.x.x>: List all active sessions by IP address
		bymac <hh:hh:hh:hh:hh:hh>: List all active sessions by MAC address
		groups: List all User Groups
		usergroups <username>: List user's groups
		topics: List topics available for subscription
		subscribe <topic>: Subscribe to a topic
		"""
		validOptions={'all':1,'byip':2,'bymac':2,'groups':1,'usergroups':2,'topics':1,'subscribe':2}
		args=line.split()
		if line and args[0] in validOptions and len(args)==validOptions[args[0]]:
			if args[0]=='all':
				self.printJSON(self.api.getSessions())
			if args[0]=='byip':
				self.printJSON(self.api.getSessionByIpAddress(args[1]))
			if args[0]=='bymac':
				self.printJSON(self.api.getSessionByMacAddress(args[1]))
			if args[0]=='groups':
				self.printJSON(self.api.getUserGroups())
			if args[0]=='usergroups':
				self.printJSON(self.api.getUserGroupByUserName(args[1]))
			if args[0]=='topics':
				self.printTopics(pxGridServices.session)
			if args[0]=='subscribe':
				self.topicSubscribe(pxGridServices.session,args[1])
		else:
			print("Invalid command. See help session")

	def do_anc(self,line):
		""""anc options:
		policies: List all ANC policies
		policybyname <name>: List policy by name
		create <name> <action>: Create new policy. Action must be QUARANTINE, SHUT_DOWN or PORT_BOUNCE
		delete <name>: Delete policy
		endpoints: List endpoints assigned to policies
		endpointpolicies: List endpoints policy assignment by MAC address on a specific device (NAS-IP-Address)
		endpointsbymac <hh:hh:hh:hh:hh:hh>: List policy assigned to MAC address
		endpointsbynas <hh:hh:hh:hh:hh:hh> <x.x.x.x>: List policy assigned to a MAC address on a specific device (NAS-IP-Address)
		applybyip <name> <x.x.x.x>: Apply policy by IP address
		applybymac <name> <hh:hh:hh:hh:hh:hh>: Apply policy by MAC address
		applybynas <name> <hh:hh:hh:hh:hh:hh> <x.x.x.x>: Apply policy by MAC address on a specific device (NAS-IP-Address)
		clearbymac <hh:hh:hh:hh:hh:hh>: Clear policy by MAC address
		clearbynas <hh:hh:hh:hh:hh:hh> <x.x.x.x>: Clear policy by MAC address a specific device (NAS-IP-Address)
		topics: List topics available for subscription
		subscribe <topic>: Subscribe to a topic
		"""
		validOptions={'policies':1,'policybyname':2,'create':3,'delete':2,'endpoints':1,'endpointpolicies':1,'endpointsbymac':2,'endpointsbynas':3,'applybyip':3,'applybymac':3,'applybynas':4,'clearbymac':2,'clearbynas':3,'topics':1,'subscribe':2}
		args=line.split()
		if line and args[0] in validOptions and len(args)==validOptions[args[0]]:
			if args[0]=='policies':
				self.printJSON(self.api.ancGetPolicies())
			if args[0]=='policybyname':
				self.printJSON(self.api.ancGetPolicyByName(args[1]))
			if args[0]=='create':
				self.printJSON(self.api.ancCreatePolicy(args[1],args[2]))
			if args[0]=='delete':
				self.printJSON(self.api.ancDeletePolicyByName(args[1]))
			if args[0]=='endpoints':
				self.printJSON(self.api.ancGetEndponts())
			if args[0]=='endpointpolicies':
				self.printJSON(self.api.ancGetEndpointPolicies())
			if args[0]=='endpointsbymac':
				self.printJSON(self.api.ancGetEndpontByMacAddress(args[1]))
			if args[0]=='endpointsbynas':
				self.printJSON(self.api.ancGetEndpointByNasIpAddress(args[1],args[2]))
			if args[0]=='applybyip':
				self.printJSON(self.api.ancApplyEndpointByIpAddress(args[1],args[2]))
			if args[0]=='applybymac':
				self.printJSON(self.api.ancApplyEndpointByMacAddress(args[1],args[2]))
			if args[0]=='applybynas':
				self.printJSON(self.api.ancApplyEndpointPolicy(args[1],args[2],args[3]))
			if args[0]=='clearbymac':
				self.printJSON(self.api.ancClearEndpointByMacAddress(args[1]))
			if args[0]=='clearbynas':
				self.printJSON(self.api.ancClearEndpointPolicy(args[1],args[2]))
			if args[0]=='topics':
				self.printTopics(pxGridServices.anc)
			if args[0]=='subscribe':
				self.topicSubscribe(pxGridServices.anc,args[1])
		else:
			print("Invalid command. See help anc")

	def do_mdm(self,line):
		"""mdm options:
		endpoints: List all MDM endpoints
		endpointsbymac <hh:hh:hh:hh:hh:hh>: List MDM endpoints by MAC address
		endpointsbytype <type>: List MDM endpoints by type. Type must be NON_COMPLIANT, REGISTERED or DISCONNECTED
		endpointsbyos <ostype>: List MDM endpoints by OS. OS must be ANDROID, IOS or WINDOWS
		topics: List topics available for subscription
		subscribe <topic>: Subscribe to a topic
		"""
		validOptions={'endpoints':1,'endpointsbymac':2,'endpointsbytype':2,'endpointsbyos':2,'topics':1,'subscribe':2}
		args=line.split()
		if line and args[0] in validOptions and len(args)==validOptions[args[0]]:
			if args[0]=='endpoints':
				self.printJSON(self.api.mdmGetEndpoints())
			if args[0]=='endpointsbymac':
				self.printJSON(self.api.mdmGetEndpointByMacAddress(args[1]))
			if args[0]=='endpointsbytype':
				self.printJSON(self.api.mdmGetEndpointsByType(args[1]))
			if args[0]=='endpointsbyos':
				self.printJSON(self.api.mdmGetEndpointsByOsType(args[1]))
			if args[0]=='topics':
				self.printTopics(pxGridServices.mdm)
			if args[0]=='subscribe':
				self.topicSubscribe(pxGridServices.mdm,args[1])
		else:
			print("Invalid command. See help mdm")
	
	def do_system(self,line):
		"""system options:
		healths [nodename] [starttime]: Retrieve health metrics. Optionally can be filtered by node.
			By default, last 1 hour of statistics is returned.
		perfs [nodename] [starttime]: Retrieve performance metrics. Optionally can be filtered by node.
			By default, last 1 hour of statistics is returned.
		"""
		args=line.split()
		if line and args[0] in ['healths','perfs']:
			if len(args)==2:
				nodeName=args[1]
			else:
				nodeName=None
			if len(args)==3:
				startTimestamp=args[2]
			else:
				startTimestamp=None
			if args[0]=='healths':
				self.printJSON(self.api.systemGetHealths(nodeName,startTimestamp))
			if args[0]=='perfs':
				self.printJSON(self.api.systemGetPerformances(nodeName,startTimestamp))
		else:
			print("Invalid command. See help system")
	
	def do_profiler(self,line):
		"""profiler options
			list: Retrive profiling policies
			topics: List topics available for subscription
			subscribe <topic>: Subscribe to a topic
		"""
		validOptions={'list':1,'topics':1,'subscribe':2}
		args=line.split()
		if line and args[0] in validOptions and len(args)==validOptions[args[0]]:
			if args[0]=='list':
				self.printJSON(self.api.profilerGetProfiles())
			if args[0]=='topics':
				self.printTopics(pxGridServices.profiler)
			if args[0]=='subscribe':
				self.topicSubscribe(pxGridServices.profiler,args[1])
		else:
			print("Invalid command. See help profiler")

	def do_radius(self,line):
		"""radius options:
			list [id]: Retrieve RADIUS failure statistics. Otionally specify error code
			topics: List topics available for subscription
			subscribe <topic>: Subscribe to a topic
		"""
		validOptions={'list':[1,2],'topics':[1],'subscribe':[2]}
		args=line.split()
		if line and args[0] in validOptions and len(args) in validOptions[args[0]]:
			if args[0]=='list':
				if len(args)==1:
					self.printJSON(self.api.radiusGetFailures())
				else:
					self.printJSON(self.api.radiusGetFailureById(int(args[0])))
			if args[0]=='topics':
				self.printTopics(pxGridServices.radius)
			if args[0]=='subscribe':
				self.topicSubscribe(pxGridServices.radius,args[1])
		else:
			print("Invalid command. See help radius")

	def do_trustsec(self,line):
		"""trustsec options:
		topics: List topics available for subscription
		subscribe <topic>: Subscribe to a topic
		"""
		validOptions={'topics':1,'subscribe':2}
		args=line.split()
		if line and args[0] in validOptions and len(args)==validOptions[args[0]]:
			if args[0]=='topics':
				self.printTopics(pxGridServices.trustsec)
			if args[0]=='subscribe':
				self.topicSubscribe(pxGridServices.trustsec,args[1])
		else:
			self.printJSON("Invalid command. See help trustsec")

	def do_trustseccfg(self,line):
		"""trustseccfg options:
		sgt [id]: List all Security Group Tags. Optionally filter by ID
		sgacl [id]: List all SG Access Lists. Optionally filter by ID
		policies: List all Egress policies
		matrices: List all Egress matrices
		topics: List topics available for subscription
		subscribe <topic>: Subscribe to a topic
		"""
		validOptions={'sgt':[1,2],'sgacl':[1,2],'policies':[1],'matrices':[1],'topics':[1],'subscribe':[2]}
		args=line.split()
		if line and args[0] in validOptions and len(args) in validOptions[args[0]]:
			if args[0]=='sgt':
				if len(args)==1:
					self.printJSON(self.api.trustsecGetSecurityGroups())
				else:
					self.printJSON(self.api.trustsecGetSecurityGroups(args[1]))
			if args[0]=='sgacl':
				if len(args)==1:
					self.printJSON(self.api.trustsecGetSecurityGroupAcls())
				else:
					self.printJSON(self.api.trustsecGetSecurityGroupAcls(args[1]))
			if args[0]=='policies':
				self.printJSON(self.api.trustsecGetEgressPolicies())
			if args[0]=='matrices':
				self.printJSON(self.api.trustsecGetEgressMatrices())
			if args[0]=='topics':
				self.printTopics(pxGridServices.trustsecConfig)
			if args[0]=='subscribe':
				self.topicSubscribe(pxGridServices.trustsecConfig,args[1])
		else:
			print("Invalid command. See help trustseccfg")

	def do_sxp(self,line):
		"""sxp options:
		bindings: List all SXP bindings
		topics: List topics available for subscription
		subscribe <topic>: Subscribe to a topic
		"""
		validOptions={'bindings':1,'topics':1,'subscribe':2}
		args=line.split()
		if line and args[0] in validOptions and len(args)==validOptions[args[0]]:
			if args[0]=='bindings':
				self.printJSON(self.api.trustsecGetBindings())
			if args[0]=='topics':
				self.printTopics(pxGridServices.sxp)
			if args[0]=='subscribe':
				self.topicSubscribe(pxGridServices.sxp,args[1])
		else:
			print("Invalid command. See help sxp")

	def do_config(self,line):
		"""Config options:
		save <file>: Save config to file
		load <file>: Load config from file
		apply [file]: Instatiate connection to pxGrid. Optionaly load the file and apply in one step
		show: Show current settings 
		pxnode <hostname>: Set pxGrid PSN FQDN
		name <clientname>: Set pxGrid client name
		cert <certfile>: Set client certificate file name
		key <keyfile>: Set client private key
		root [<rootfile>]: Set root CA file. Leave out <rootfile> to disable server certificate verification
		password <password>: Set password for password based authentication
		"""
		validOptions={'save':[2],'load':[2],'show':[1],'pxnode':[2],'name':[2],'cert':[2],'key':[2],'root':[1,2],'password':[2],'apply':[1,2]}
		args=line.split()
		if args[0] in validOptions and len(args) in validOptions[args[0]]:
			if args[0]=='save':
				configFile=open(args[1],'w')
				configFile.write(json.dumps(self.config))
				configFile.close()
			if args[0]=='load':
				configFile=open(args[1],'r')
				self.config=json.loads(configFile.read())
				configFile.close()
			if args[0]=='show':
				self.printJSON(self.config)
			if args[0]=='apply':
				if len(args)==2:
					configFile=open(args[1],'r')
					self.config=json.loads(configFile.read())
					configFile.close()
				self.api=pxAPI(self.config['pxGridNode'],self.config['clientName'],self.config['clientCertFile'],self.config['clientKeyFile'],self.config['rootCAFile'],self.config['password'])
			if args[0]=='pxnode':
				self.config['pxGridNode']=args[1]
			if args[0]=='name':
				self.config['clientName']=args[1]
			if args[0]=='cert':
				self.config['clientCertFile']=args[1]
			if args[0]=='key':
				self.config['clientKeyFile']=args[1]
			if args[0]=='root':
				if len(args)==2:
					self.config['rootCAFile']=args[1]
				else:
					self.config['rootCAFile']=''
			if args[0]=='password':
				self.config['password']=args[1]
		else:
			print("Invalid command. See help config")

	def do_accountcreate(self,line):
		"""Create password based account
		Client name (username) is take from config
		"""
		if self.config["clientName"]=="" or self.config["pxGridNode"]=="":
			print("clientName and pxGridNode are require for this command. Use config command")
		else:
			self.api=pxAPI(self.config['pxGridNode'],self.config['clientName'],'','',self.config['rootCAFile'])
			accountInfo=self.api.accountCreate()
			self.printJSON(accountInfo)
			self.config["password"]=accountInfo["password"]
			print("Password automatically set in the config. Use config show to verify")

	
	def do_activate(self,line):
		"""Activate will attempt to connect to pxGrid node and check if the client is approved
		wait parameter will retry activation every 60 seconds until the client is approved
		"""
		if line in ['','wait']:
			accountState=self.api.accountActivate(line=='wait')
			self.printJSON(accountState)
		else:
			print("Invalid command. See help config")

	def do_endpoint(self,line):
		"""Post endpoint asset information using Context-In
		endpoint <json>. json must be in the format documented here: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Endpoint-Asset.
		The contents of the JSON data must be combined into a single line. Example:
		Source JSON: 
		{
			"opType": "CREATE",
			"asset": {
				"assetId": 1,
				"assetName": "IOT1",
				"assetIpAddress": "1.2.3.4",
				"assetMacAddress": "33:44:55:66:77:88",
				"assetVendor": "CL",
				"assetHwRevision": "1.0",
				"assetSwRevision": "2.0",
				"assetProtocol": "Telnet",
				"assetProductId": "Wifi-IOT",
				"assetSerialNumber": "ABC12345",
				"assetDeviceType": "WiFi",
				"assetConnectedLinks": [
					{
						"key": "wifi1",
						"value": "ssid1"
					}
				]
			}
		}
		Command:
		endpoint {"opType": "CREATE","asset": {"assetId": 1,"assetName": "IOT1","assetIpAddress": "1.2.3.4","assetMacAddress": "33:44:55:66:77:88","assetVendor": "CL","assetHwRevision": "1.0","assetSwRevision": "2.0","assetProtocol": "Telnet","assetProductId": "Wifi-IOT","assetSerialNumber": "ABC12345","assetDeviceType": "WiFi","assetConnectedLinks": [{"key": "wifi1","value": "ssid1"}]}}
		"""
		endpoint_data=json.dumps(json.loads(line))

		pubsub=self.api.serviceLookup("com.cisco.ise.pubsub")
		wsUrl=pubsub["services"][0]["properties"]["wsUrl"]
		nodeName=pubsub["services"][0]["nodeName"]
		secret=self.api.getAccessSecret(nodeName)
		ssl_context=ssl.create_default_context()
		ssl_context.load_verify_locations(cafile=self.config['rootCAFile'])
		ws=websocket.create_connection(wsUrl,
			sslopt={"context": ssl_context},
			header={"Authorization": "Basic "+b64encode((f"{self.config['clientName']}:{secret}").encode()).decode()}
		)
		frame=stompFrame("CONNECT",{
			"accept-version": "1.2",
			"host": nodeName
			},
		)
		ws.send(frame.getFrame(),websocket.ABNF.OPCODE_BINARY)
		frame=stompFrame("SEND",{
			"destination": "/topic/com.cisco.endpoint.asset",
			"content-length": str(len(endpoint_data))
			},
			endpoint_data
		)
		print(ws.recv())
		ws.send(frame.getFrame(),websocket.ABNF.OPCODE_BINARY)
		ws.close()

	def do_debug(self,line):
		"""enable verbose http and websocket messages"""
		http_client.HTTPConnection.debuglevel = 1
		logging.basicConfig()
		logging.getLogger().setLevel(logging.DEBUG)
		requests_log = logging.getLogger("requests.packages.urllib3")
		requests_log.setLevel(logging.DEBUG)
		requests_log.propagate = True
		logger = logging.getLogger('websockets')
		logger.setLevel(logging.DEBUG)
		logger.addHandler(logging.StreamHandler())
		websocket.enableTrace(True)

	def do_EOF(self,line):
		return(True)
	
	def postloop(self):
		print("Good bye")

if __name__=='__main__':
	pxShell().cmdloop()
