# pxAPI Library

This library simplifies interaction with ISE pxGrid

Additonal reference material:
* https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki
* https://developer.cisco.com/docs/pxgrid/

## Limitations

* No support for subscribing to topics. Will be added soon
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

pxAPI.py file has comments throughout describing all functions
All data is returned in the original form, converted to python dict

```python
#!/usr/bin/env python3
from pxAPI import pxAPI

# Instatiate object
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

# pxShell.py

This utility is an interactive wrapper for pxAPI library. It allows interaction with pxGrid using simple CLI interface.

## Usage

All commands are document and help can be retrived using help <command>
```
./pxShell.py
pxShell> help

Documented commands (type help <topic>):
========================================
activate  config  help  profiles  session  trustsec
anc       debug   mdm   radius    system 

Undocumented commands:
======================
EOF

pxShell> help config
Config options:
                save <file>: Save config to file
                load <file>: Load config from file
                show: Show current settings 
                pxnode <hostname>: Set pxGrid PSN FQDN
                name <clientname>: Set pxGrid client name
                cert <certfile>: Set client certificate file name
                key <keyfile>: Set client private key
                root <rootfile>: Set root CA file
                apply: instatiate connection to pxGrid

```

Before the utility can interface with pxGrid, it has to be configured with pxGrid information and certificates
This is done with config command. The config can also be save and loaded from a file. The file is in human readable json format.

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
```
Additional examples
```
pxShell> activate
Account is enabled
pxShell> anc create Restrict QUARANTINE
{'name': 'Restrict', 'actions': ['QUARANTINE']}
pxShell> anc policies
{'policies': [{'name': 'Quarantine', 'actions': ['QUARANTINE']}, {'name': 'Restrict', 'actions': ['QUARANTINE']}, {'name': 'Shutdown', 'actions': ['SHUT_DOWN']}]}
pxShell> anc delete Restrict
{}
pxShell> anc policies
{'policies': [{'name': 'Quarantine', 'actions': ['QUARANTINE']}, {'name': 'Shutdown', 'actions': ['SHUT_DOWN']}]}
pxShell> session all
{'sessions': [{'timestamp': '2020-09-29T22:45:45.489-04:00', 'state': 'STARTED', 'userName': '18:60:24:00:00:02', 'callingStationId': '18:60:24:00:00:02', 'calledStationId': '88:5A:92:7F:BF:82', 'auditSessionId': 'AC1F01070000005FDCE6C13E', 'ipAddresses': ['172.31.8.150'], 'macAddress': '18:60:24:00:00:02', 'nasIpAddress': '172.31.1.7', 'nasPortId': 'GigabitEthernet1/0/2', 'nasIdentifier': 'sw4', 'nasPortType': 'Ethernet', 'endpointProfile': 'HP-Kali', 'adNormalizedUser': '18:60:24:00:00:02', 'providers': ['None'], 'endpointCheckResult': 'none', 'identitySourcePortStart': 0, 'identitySourcePortEnd': 0, 'identitySourcePortFirst': 0, 'serviceType': 'Call Check', 'networkDeviceProfileName': 'Cisco', 'radiusFlowType': 'WiredMAB', 'mdmRegistered': False, 'mdmCompliant': False, 'mdmDiskEncrypted': False, 'mdmJailBroken': False, 'mdmPinLocked': False, 'selectedAuthzProfiles': ['Quarantine']}]}
```