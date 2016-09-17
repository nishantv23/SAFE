#!/usr/bin/env python
"""
Created on 26-Feb-2014

@author: sudarshans
"""
from __future__ import print_function

import BaseHTTPServer
import cgi
import subprocess

accounts = {
    'sudarshan': 'sudarshan',
    'adityakamath': 'adityakamath'
}


class AuthHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
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

        # Retrieve username and password from POST request
        username = form['username'].value
        password = form['password'].value

        # Check if the user has provided valid credentials
        if username in accounts and accounts[username] == password:
            self.wfile.write(
                "<html>"
                "<body>"
                "Authentication succeeded with username " + username +
                "</body>"
                "</html>"
            )
            get_mac_command = "arp -n|grep {0}|grep -o '..:..:..:..:..:..'"
            process = subprocess.Popen(get_mac_command.format(self.client_address[0]),stdout=subprocess.PIPE,shell=True)
            client_mac_address = process.communicate()[0]
            self.server.controller.host_has_authenticated(self.client_address[0],client_mac_address)
        else:
            self.wfile.write(
                "<html>"
                "<body>"
                "Authentication failed! Please double check your username and password and try again"
                "</body>"
                "</html>"
            )
        self.wfile.close()
