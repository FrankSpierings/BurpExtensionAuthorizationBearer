from burp import IBurpExtender
from burp import IHttpListener	

_bearer = dict()
_AUTHORIZATION_HEADER = 'Authorization: Bearer'

class BurpExtender(IBurpExtender, IHttpListener):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		self._callbacks.setExtensionName('Authorization Bearer')
		self._callbacks.registerHttpListener(self)
		print "Give me all your moneys or I will eat your cookies!"
		return

	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		bearerdomain = "%s://%s:%d" % (messageInfo.getHttpService().getProtocol(), \
									   messageInfo.getHttpService().getHost(), \
									   messageInfo.getHttpService().getPort())
		if messageIsRequest:
			#Replace the request token with the most recent.
			if bearerdomain in _bearer.keys():
				found = False
				requestInfo = self._helpers.analyzeRequest(messageInfo.getRequest())
				headers 	= list(requestInfo.getHeaders())
				for header in headers:
					if header.startswith(_AUTHORIZATION_HEADER):
						if (header != _bearer[bearerdomain]):
							print "[+] Replacing: %s" % (header)
							print "[+] With:      %s" % (_bearer[bearerdomain])
							i = headers.index(header)
							headers.pop(i)
							headers.insert(i, _bearer[bearerdomain])
							body = messageInfo.getRequest()[requestInfo.getBodyOffset():]
							bodyStr = self._helpers.bytesToString(body)
							newRequest = self._helpers.buildHttpMessage(headers, bodyStr)
							messageInfo.setRequest(newRequest)
						found = True
						break
				if (not found):
					#We could add it here.
					pass
		else:
			#Grab the authorization bearer and store it.
			responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
			headers 	 = list(responseInfo.getHeaders())
			for header in headers:
				if header.startswith(_AUTHORIZATION_HEADER):
					_bearer[bearerdomain] = header
					print "[+] Grabbed: %s = %s" % (bearerdomain, header)
					break
		return