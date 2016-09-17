#!/usr/bin/env python

from __future__ import print_function

import BaseHTTPServer
import cgi
import subprocess
import re
import json

accounts = {
    'sudarshan': 'sudarshan',
    'adityakamath': 'adityakamath'
}

def validate_mac(mac):
	if re.match("[0-9a-f]{2}([:][0-9a-f]{2}){5}$",mac.lower()):
		return True
	else:
		return False

class MacAuthRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        """
        Will be called whenever a HTTP GET request is received
        self.path contains the URL requested, relative to the site root
        Response must be written to the file like object self.wfile
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(
            "<html>"
            "<body>"
            "<form action='/' method='post'>"
            "<input name='username' type=text placeholder='User Name'/><br>"
            "<input name='password' type=password placeholder='Password'/><br>"
	    "<input name='mac' type=text placeholder='MAC address'/><br>"
            "<button type='submit'>Submit!</button>"
            "</form>"
            "</body>"
            "</html>")
        self.wfile.close()

    def do_POST(self):
        """
        Will be called whenever a HTTP POST request is received
        Response must be written to the file like object self.wfile
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type'], })

        # Retrieve username, password and mac address for preauthentication from POST request
        username = form['username'].value
        password = form['password'].value
	preauth_mac = form['mac'].value

        # Check if the user has provided valid credentials
        if username in accounts and accounts[username] == password:
	    if validate_mac(preauth_mac) == True:
		self.wfile.write(
		    "<html>"
                    "<body>"
                    "Authentication succeeded with username " + username +
		    "<br>The device is added to the preauthenticated devices list"
                    "</body>"
                    "</html>"
            	)
		
		preauthenticated_mac = []
		try:
		    pre_auth_list = open("preauthenticated_mac.json","r")
		    preauthenticated_mac = json.load(pre_auth_list)
		    pre_auth_list.close()
		except:
		    pass
		preauthenticated_mac.append(preauth_mac)
		f = open("preauthenticated_mac.json","w")
		f.write(json.dumps(preauthenticated_mac,indent=4))
		f.close()

	    else:
		self.wfile.write(
                "<html>"
                "<body>"
		"invalid MAC address encountered <br> example - ff:ff:ff:ff:ff:ff"
                "</body>"
                "</html>"
            	)	
        else:
            self.wfile.write(
                "<html>"
                "<body>"
                "Authentication failed! Please double check your username and password and try again"
                "</body>"
                "</html>"
            )
        self.wfile.close()


server = BaseHTTPServer.HTTPServer(('',8001),MacAuthRequestHandler)
server.serve_forever()
