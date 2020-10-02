#!/usr/bin/env python3
from pxAPI import pxAPI,stompFrame
import signal
import asyncio
from asyncio.tasks import FIRST_COMPLETED
from websockets import ConnectionClosed
import logging

async def futureReadMessage(api, future):
	"""Callback function that's called upon receiving data from pxGrid"""
	try:
		frame = await api.stompRead()
		future.set_result(frame)
	except ConnectionClosed:
		print('Websocket connection closed')

async def subscribeLoop(api,serviceName,topicName):
	await api.topicSubscribe(serviceName,topicName)
	print("Ctrl-C to disconnect...")
	while True:
		future = asyncio.Future()
		futureRead = futureReadMessage(api, future)
		try:
			#Wait until data is received
			await asyncio.wait([futureRead],return_when=FIRST_COMPLETED)
		except asyncio.CancelledError:
			await api.stompDisconnect('123')
			break
		else:
			#Retrieve results of the call back function
			frame = future.result()
			print("Received Packet: command={} content={}".format(frame.command,frame.data))

api=pxAPI('pxgridnode.example.com','client-name','client.cer','client.key','root.cer')

loop = asyncio.get_event_loop()
#Initialize async function
subscribeTask = asyncio.ensure_future(subscribeLoop(api,'com.cisco.ise.session','sessionTopic'))
loop.add_signal_handler(signal.SIGINT,subscribeTask.cancel)
loop.add_signal_handler(signal.SIGTERM,subscribeTask.cancel)
#Wait until the function finishes due to cancellation (^C) or another error 
loop.run_until_complete(subscribeTask)