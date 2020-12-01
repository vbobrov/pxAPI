# pxAPI Library

This library simplifies interaction with ISE pxGrid

Additonal reference material:
* https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki
* https://developer.cisco.com/docs/pxgrid/

## Limitations

* No support for password authentication. Certificate authentication required
* Private key must be unencrypted

## Installation

```
# Download
git clone https://github.com/vbobrov/pxAPI
cd pxAPI

# Optionally create virtual env
python3 -m venv env

# Install requirements
pip3 install -r requirements.txt
```

## Usage

pxAPI.py file has comments throughout describing all functions.  
All data is returned in the original form, converted to python dict

### REST API
These are fairly straight forward. Review the comments in the code for reference.

```python
#!/usr/bin/env python3
from pxAPI import pxAPI

# Instatiate object. Root CA argument can be omitted to disable server certificate verification.
api=pxAPI('pxgridnode.example.com','client-name','client.cer','client.key','root.cer')

# Check account activation status. This will connect to pxGrid node and check if our account is in approved and enabled state
# With this default usage, the function will return immediately with either True or False on the state of the account
api.accountActivate()

# Optionally, function can wait until the account is approved and retry every 60 seconds
api.accountActivate(True)

# Some examples
# Retrive all sessions
print(api.getSessions())

# Retrieve all Trustsec egress policies
print(api.trustsecGetEgressPolicies())

# Retrive all NON-Compliant MDM endpoints
print(api.mdmGetEndpointsByType('NON-COMPLIANT'))
```

### Subscribing to pxGrid topics

ISE uses web sockets as a mechanism for exchange real-time data with pxGrid clients  
Websocket python library utilizes asyncio library for asynchronoous communication  
When data is received from ISE, it is passed into a callback function which processes the data  

subscribe.py file contains a full example to subscribe to Session Topic

# pxShell.py

This utility is an interactive wrapper for pxAPI library. It allows interaction with pxGrid using simple CLI interface.

## Usage

All commands are document and help can be retrived using help &lt;command&gt;
```
./pxShell.py
pxShell> help

Documented commands (type help <topic>):
========================================
activate  config  help  profiler  session  system    trustseccfg
anc       debug   mdm   radius    sxp      trustsec

Undocumented commands:
======================
EOF

pxShell> help config
Config options:
                save <file>: Save config to file
                load <file>: Load config from file
                apply [file]: Instatiate connection to pxGrid. Optionaly load the file and apply in one step
                show: Show current settings 
                pxnode <hostname>: Set pxGrid PSN FQDN
                name <clientname>: Set pxGrid client name
                cert <certfile>: Set client certificate file name
                key <keyfile>: Set client private key
                root [<rootfile>]: Set root CA file. Leave out <rootfile> to disable server certificate verification
```

Before the utility can interface with pxGrid, it has to be configured with pxGrid information and certificates.  
This is done with config command. The config can also be saved and loaded from a file. The file is in human readable json format.  
config apply command must be used to instantiate the API connection.

```
pxShell> config pxnode pxgridnode.example.com
pxShell> config name client-name
pxShell> config cert client.cer
pxShell> config key client.key
pxShell> config root root.cer
pxShell> config show
{'clientName': 'client-name', 'pxGridNode': 'pxgridnode.example.com', 'clientCertFile': 'client.cer', 'clientKeyFile': 'client.key', 'rootCAFile': 'root.cer'}
pxShell> config save px.cfg
pxShell> config load px.cfg
pxShell> config apply <--config apply command is used to create the api object with the requested parameters
pxShell> config apply px.cfg <--config apply can load the config file in one step

```
### Examples

Check if account is approved in ISE
```
pxShell> activate
Account is enabled
```
Working with ANC
```
pxShell> anc create Restrict QUARANTINE
{'name': 'Restrict', 'actions': ['QUARANTINE']}
pxShell> anc policies
{'policies': [{'name': 'Quarantine', 'actions': ['QUARANTINE']}, {'name': 'Restrict', 'actions': ['QUARANTINE']}, {'name': 'Shutdown', 'actions': ['SHUT_DOWN']}]}
pxShell> anc delete Restrict
{}
pxShell> anc policies
{'policies': [{'name': 'Quarantine', 'actions': ['QUARANTINE']}, {'name': 'Shutdown', 'actions': ['SHUT_DOWN']}]}
pxShell> anc topics
statusTopic
pxShell> anc subscribe statusTopic
Ctrl-C to disconnect...
Received Packet: command=CONNECTED content=
Received Packet: command=MESSAGE content={"operationId":"vb-ise-pan1.vblan.com:35","macAddress":"11:22:33:44:55:66","status":"SUCCESS","policyName":"Quarantine"}
Received Packet: command=MESSAGE content={"operationId":"vb-ise-pan1.vblan.com:36","macAddress":"11:22:33:44:55:66","status":"SUCCESS"}
```
Working with sessions
```
pxShell> session all
{'sessions': [{'timestamp': '2020-09-29T22:45:45.489-04:00', 'state': 'STARTED', 'userName': '18:60:24:00:00:02', 'callingStationId': '18:60:24:00:00:02', 'calledStationId': '88:5A:92:7F:BF:82', 'auditSessionId': 'AC1F01070000005FDCE6C13E', 'ipAddresses': ['172.31.8.150'], 'macAddress': '18:60:24:00:00:02', 'nasIpAddress': '172.31.1.7', 'nasPortId': 'GigabitEthernet1/0/2', 'nasIdentifier': 'sw4', 'nasPortType': 'Ethernet', 'endpointProfile': 'HP-Kali', 'adNormalizedUser': '18:60:24:00:00:02', 'providers': ['None'], 'endpointCheckResult': 'none', 'identitySourcePortStart': 0, 'identitySourcePortEnd': 0, 'identitySourcePortFirst': 0, 'serviceType': 'Call Check', 'networkDeviceProfileName': 'Cisco', 'radiusFlowType': 'WiredMAB', 'mdmRegistered': False, 'mdmCompliant': False, 'mdmDiskEncrypted': False, 'mdmJailBroken': False, 'mdmPinLocked': False, 'selectedAuthzProfiles': ['Quarantine']}]}

pxShell> session topics
sessionTopic
groupTopic
pxShell> session subscribe sessionTopic
Ctrl-C to disconnect...
Received Packet: command=CONNECTED content=
Received Packet: command=MESSAGE content={"sessions":[{"timestamp":"2020-10-02T16:41:03.984-04:00","state":"STARTED","userName":"18:60:24:00:00:02","callingStationId":"18:60:24:00:00:02","calledStationId":"88:5A:92:7F:BF:82","auditSessionId":"AC1F010700000068EB0BEF16","ipAddresses":["172.31.8.150"],"macAddress":"18:60:24:00:00:02","nasIpAddress":"172.31.1.7","nasPortId":"GigabitEthernet1/0/2","nasIdentifier":"sw4","nasPortType":"Ethernet","ancPolicy":"Quarantine","endpointProfile":"HP-Kali","adNormalizedUser":"18:60:24:00:00:02","providers":["None"],"endpointCheckResult":"none","identitySourcePortStart":0,"identitySourcePortEnd":0,"identitySourcePortFirst":0,"serviceType":"Call Check","networkDeviceProfileName":"Cisco","radiusFlowType":"WiredMAB","mdmRegistered":false,"mdmCompliant":false,"mdmDiskEncrypted":false,"mdmJailBroken":false,"mdmPinLocked":false,"selectedAuthzProfiles":["Quarantine"]}]}
Received Packet: command=MESSAGE content={"sessions":[{"timestamp":"2020-10-02T16:41:13.199-04:00","state":"DISCONNECTED","userName":"18:60:24:00:00:02","callingStationId":"18:60:24:00:00:02","calledStationId":"88:5A:92:7F:BF:82","auditSessionId":"AC1F010700000068EB0BEF16","ipAddresses":["172.31.8.150"],"macAddress":"18:60:24:00:00:02","nasIpAddress":"172.31.1.7","nasPortId":"GigabitEthernet1/0/2","nasIdentifier":"sw4","nasPortType":"Ethernet","ancPolicy":"Quarantine","endpointProfile":"HP-Kali","adNormalizedUser":"18:60:24:00:00:02","providers":["None"],"endpointCheckResult":"none","identitySourcePortStart":0,"identitySourcePortEnd":0,"identitySourcePortFirst":0,"serviceType":"Call Check","networkDeviceProfileName":"Cisco","radiusFlowType":"WiredMAB","mdmRegistered":false,"mdmCompliant":false,"mdmDiskEncrypted":false,"mdmJailBroken":false,"mdmPinLocked":false,"selectedAuthzProfiles":["Quarantine"]}]}
```
Working with Trustsec config
```
pxShell> trustseccfg sgt
{'securityGroups': [{'id': '92bb1950-8c01-11e6-996c-525400b48521', 'name': 'ANY', 'description': 'Any Security Group', 'tag': 65535}, {'id': '934557f0-8c01-11e6-996c-525400b48521', 'name': 'Auditors', 'description': 'Auditor Security Group', 'tag': 9}, {'id': '935d4cc0-8c01-11e6-996c-525400b48521', 'name': 'BYOD', 'description': 'BYOD Security Group', 'tag': 15}, {'id': '9370d4c0-8c01-11e6-996c-525400b48521', 'name': 'Contractors', 'description': 'Contractor Security Group', 'tag': 5}, {'id': '93837260-8c01-11e6-996c-525400b48521', 'name': 'Developers', 'description': 'Developer Security Group', 'tag': 8}, {'id': '9396d350-8c01-11e6-996c-525400b48521', 'name': 'Development_Servers', 'description': 'Development Servers Security Group', 'tag': 12}, {'id': '93ad6890-8c01-11e6-996c-525400b48521', 'name': 'Employees', 'description': 'Employee Security Group', 'tag': 4}, {'id': '93c66ed0-8c01-11e6-996c-525400b48521', 'name': 'Guests', 'description': 'Guest Security Group', 'tag': 6}, {'id': '93e1bf00-8c01-11e6-996c-525400b48521', 'name': 'Network_Services', 'description': 'Network Services Security Group', 'tag': 3}, {'id': '93f91790-8c01-11e6-996c-525400b48521', 'name': 'PCI_Servers', 'description': 'PCI Servers Security Group', 'tag': 14}, {'id': '940facd0-8c01-11e6-996c-525400b48521', 'name': 'Point_of_Sale_Systems', 'description': 'Point of Sale Security Group', 'tag': 10}, {'id': '9423aa00-8c01-11e6-996c-525400b48521', 'name': 'Production_Servers', 'description': 'Production Servers Security Group', 'tag': 11}, {'id': '9437a730-8c01-11e6-996c-525400b48521', 'name': 'Production_Users', 'description': 'Production User Security Group', 'tag': 7}, {'id': '944b2f30-8c01-11e6-996c-525400b48521', 'name': 'Quarantined_Systems', 'description': 'Quarantine Security Group', 'tag': 255}, {'id': '94621290-8c01-11e6-996c-525400b48521', 'name': 'Test_Servers', 'description': 'Test Servers Security Group', 'tag': 13}, {'id': '947832a0-8c01-11e6-996c-525400b48521', 'name': 'TrustSec_Devices', 'description': 'TrustSec Devices Security Group', 'tag': 2}, {'id': '92adf9f0-8c01-11e6-996c-525400b48521', 'name': 'Unknown', 'description': 'Unknown Security Group', 'tag': 0}]}
pxShell> trustseccfg topics
securityGroupVnVlanTopic
securityGroupTopic
securityGroupAclTopic
pxShell> trustseccfg subscribe securityGroupTopic
Ctrl-C to disconnect...
Received Packet: command=CONNECTED content=
Received Packet: command=MESSAGE content={"operation":"CREATE","securityGroup":{"id":"05000d80-04ea-11eb-8d63-1a05c3bba070","name":"hackers","description":"","tag":16}}
Received Packet: command=MESSAGE content={"operation":"DELETE","securityGroup":{"id":"05000d80-04ea-11eb-8d63-1a05c3bba070","name":"hackers","description":"","tag":16}}
```
Working with profiler
```
pxShell> profiler topics
topic
pxShell> profiler subscribe topic
Ctrl-C to disconnect...
Received Packet: command=CONNECTED content=
Received Packet: command=MESSAGE content={"operation":"CREATE","profile":{"id":"4fd41a00-04ee-11eb-8d63-1a05c3bba070","name":"test-device","fullName":"test-device"}}
Received Packet: command=MESSAGE content={"operation":"DELETE","profile":{"id":"4fd41a00-04ee-11eb-8d63-1a05c3bba070","name":"test-device","fullName":"test-device"}}
```