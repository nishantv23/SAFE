"""
Created on 17-Feb-2014

@author: adityakamath
"""
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import BaseHTTPServer
import threading
import subprocess
import auth
import init_cisco
import code2
import json 

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from serv import AuthHTTPRequestHandler


mac_port_authenticated = {}
mac_port_unauthenticated = {}
cisco_port_to_mac = {}
cisco_mac = {}
mac_to_slice = {}
switch_db = {}
preauthenticated_mac = []
allow_preauth = False
TRUNK = 2147483647
AUTHENTICATED_SLICE = 2
UNTRUSTED_SLICE = 3

class Switch:
    """
    Represents a switch.
    Contains a map from destination MAC address to port,
    and a bidirectional map from port number to slice number

    .. note ::
      Trunk slices are represented by the special integer TRUNK,
      defined as 2^31-1 = 2147483647.
    """

    def __init__(self):
        self.dest_mac_to_port = {}
        self.port_to_slice = {}
        self.slice_to_ports = {}


class SDNProject(app_manager.RyuApp):
    _CONTEXTS = {
        'dpset': dpset.DPSet
    }

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def save_backup_ports_and_slice(self):
    	backup_file = open('ports_and_slice_backup.json','w')
    	backup_file.write("[{\n")
    	comma_flag=0
        for dpid in switch_db.keys():
    	    if comma_flag != 0:
                backup_file.write(",")
    	    backup_file.write("\""+str(dpid)+"\":")
    	    temp_switch = switch_db[dpid]
    	    backup_file.write("{\"port_to_slice\":")
    	    backup_file.write(json.dumps(temp_switch.port_to_slice,indent=4))
    	    backup_file.write(",\"slice_to_ports\":")
    	    backup_file.write(json.dumps(temp_switch.slice_to_ports,indent=4))
    	    backup_file.write("}")
    	    comma_flag = comma_flag+1

    	backup_file.write("\n},\n"+str(self.unauth_slice)+"]")
    	backup_file.close()

    def save_backup_auth_info(self):
        backup_file = open('auth_info_backup.json','w')
        backup_file.write("{\n\"mac_port_authenticated\":")
        backup_file.write(json.dumps(mac_port_authenticated,indent=4))
        backup_file.write(",\n")
        
        backup_file.write("\"mac_port_unauthenticated\":")
        backup_file.write(json.dumps(mac_port_unauthenticated,indent=4))
        backup_file.write(",\n")

        backup_file.write("\"mac_to_slice\":")
        backup_file.write(json.dumps(mac_to_slice,indent=4))
        backup_file.write("\n")

        backup_file.write("}")
        backup_file.close()

    def __init__(self, *args, **kwargs):
        # Call base class initializer
        super(SDNProject, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']


        # Initiate the background authentication server
        server_address = ('', 8000)
        httpd = BaseHTTPServer.HTTPServer(server_address, AuthHTTPRequestHandler)
        httpd.controller = self
        authenticator_thread = threading.Thread(target=httpd.serve_forever)
        authenticator_thread.daemon = True
        authenticator_thread.start()
        '''
	cisco = code2.Monitor(self.cisco_portdown_callback)
        cisco_thread = threading.Thread(target=cisco.start)
        cisco_thread.daemon = True
        cisco_thread.start()
	'''

        # Load the topology
        topo = open('topo.txt', 'r')
        self.unauth_slice = 4
        restore_backup = False
        line_count = 0
        # Each line represents a switch
        for switch in topo.readlines():
	    # Check for resore_backup option
            if line_count == 0:
		s = switch.split('\n')[0]
                if s.split('=')[0]=="Restore_backup" and s.split('=')[1]=="true":
                    restore_backup = True
                line_count=line_count+1
	    
	    # Check for allow preauthenticated mac
	    elif line_count == 1:
		s = switch.split('\n')[0]
		if s.split('=')[0]=="Allow_preauth" and s.split('=')[1]=="true":
		    global allow_preauth
		    allow_preauth = True
		line_count=line_count+1

            else:
                # Get the port to slice mapping for the current switch
                port_to_slice = switch.split(',')
                dpid = int(port_to_slice[0])
                switch_db[dpid] = Switch()

                # Iterate over each port
                for currentPort in xrange(1, len(port_to_slice)):
                    port_and_slice = port_to_slice[currentPort].split(':')
                    port_number = int(port_and_slice[0])
                    slice_id = int(port_and_slice[1])
                    switch_db[dpid].port_to_slice[port_number] = slice_id
                    if slice_id not in switch_db[dpid].slice_to_ports.keys():
                        switch_db[dpid].slice_to_ports[slice_id] = []
                    switch_db[dpid].slice_to_ports[slice_id].append(port_number)

        # Read from backup files and restore state before crash
        if restore_backup == True:
	    print "Restoring backup .."
	    consistancy_flag = True
	    try:
		test = open('ports_and_slice_backup.json','r')
		test.close()
		test = open('auth_info_backup.json','r')
		test.close()
	    except IOError:
		print "Proper backup files not found, skipping restoring"
		consistancy_flag = False
	    
	    if consistancy_flag == True:
            	backup_file = open('ports_and_slice_backup.json','r')
            	backup_data = json.load(backup_file)
            	self.unauth_slice = backup_data[1]
            	backup_data = backup_data[0]

            	for dpid in backup_data:
                	for port in backup_data[dpid]['port_to_slice']:
                    		switch_db[int(dpid)].port_to_slice[int(port)] = backup_data[dpid]['port_to_slice'][port]

                	for slice in backup_data[dpid]['slice_to_ports']:
                    		switch_db[int(dpid)].slice_to_ports[int(slice)] = backup_data[dpid]['slice_to_ports'][slice]
            			backup_file.close()

            	backup_file = open('auth_info_backup.json','r')
            	backup_data = json.load(backup_file)

            	mac_port_authenticated = backup_data['mac_port_authenticated']
            	mac_port_unauthenticated = backup_data['mac_port_unauthenticated']
            	mac_to_slice = backup_data['mac_to_slice']
            	backup_file.close()
        
	'''
        p1 = subprocess.Popen(['/bin/bash','/home/mininet/sdn_project/get_authserv_mac.sh'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
        authserv_mac_normal = p1.communicate()[0]
        authserv_mac = auth.cisco_format(authserv_mac_normal)
        print ("auth server mac ",authserv_mac)
        init_cisco.init(authserv_mac)
	'''
	# Read from preauthenticated MAC adresses list exported by third party-apps 
	if allow_preauth == True:
		try:	
			pre_auth_list = open('preauthenticated_mac.json','r')
			global preauthenticated_mac
			preauthenticated_mac = json.load(pre_auth_list)
       			pre_auth_list.close()
		except:
			print "Error loading preauthenticated MAC adresses"

    def host_has_authenticated(self, ip, mac):
        """
        Will be called whenever a host with IP address `ip` authenticates successfully
        """
        print("IP Address", ip,"MAC Address", mac, "has authenticated!")
        mac_port_authenticated[mac.strip()] = None
        mac = mac.strip()
        if mac not in cisco_mac:
            src_mac = mac.strip()
            mac_to_slice[src_mac] = AUTHENTICATED_SLICE
            for switch in switch_db.values():
                if src_mac in switch.dest_mac_to_port:
                    port = switch.dest_mac_to_port[src_mac]
                    orig_slice = switch.port_to_slice[port]
                    # Non TRUNK port ensures that we modify the switch port where host is connected
                    if orig_slice != TRUNK:
                        # Changing the port status to authenticated
                        switch.port_to_slice[port] = AUTHENTICATED_SLICE
                        switch.slice_to_ports[orig_slice].remove(port)
                        if AUTHENTICATED_SLICE not in switch.slice_to_ports:
                            switch.slice_to_ports[AUTHENTICATED_SLICE] = []
                        if port not in switch.slice_to_ports[AUTHENTICATED_SLICE]:
                            switch.slice_to_ports[AUTHENTICATED_SLICE].append(port)
            #To remove any existing flow rules related to the newly authenticated host
            ''' for dpid in switch_db.keys():
                datapath = self.dpset.get(dpid)
                # Get the OpenFlow protocol instance
                ofproto = datapath.ofproto

                # Create a match rule that matches destination MAC
                match = datapath.ofproto_parser.OFPMatch(dl_dst=haddr_to_bin(src_mac))

                # Create a flow mod message
                flow_mod = datapath.ofproto_parser.OFPFlowMod(
                    datapath=datapath, match=match, cookie=0,
                    command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0,
                    priority=ofproto.OFP_DEFAULT_PRIORITY,
                    flags=ofproto.OFPFF_SEND_FLOW_REM)

                # ... and send it
                datapath.send_msg(flow_mod)
	    '''

        else:
            mac_to_slice[mac] = AUTHENTICATED_SLICE
            mac_cisco = auth.cisco_format(mac)
            switch_interface = auth.get_cisco_port(mac_cisco)
            cisco_port_to_mac[switch_interface] = mac
            auth.authenticate(switch_interface,mac_cisco)
	print ("Host ",ip,"Successfully authenticated") 
        self.save_backup_ports_and_slice()
        self.save_backup_auth_info()

    def cisco_portdown_callback(self,port):
        print(port)
        print(cisco_port_to_mac)
        if port not in cisco_port_to_mac:
                return
        mac = cisco_port_to_mac[port]
        del(cisco_mac[mac])
        del(mac_to_slice[mac])
        auth.deauthenticate(port,mac)
        #To remove any existing flow rules related to the newly authenticated host
        for dpid in switch_db.keys():
            datapath = self.dpset.get(dpid)
            # Get the OpenFlow protocol instance
            ofproto = datapath.ofproto

            # Create a match rule that matches destination MAC
            match = datapath.ofproto_parser.OFPMatch(dl_dst=haddr_to_bin(mac))

            # Create a flow mod message
            flow_mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0,
                priority=ofproto.OFP_DEFAULT_PRIORITY,
                flags=ofproto.OFPFF_SEND_FLOW_REM)

            # ... and send it
            datapath.send_msg(flow_mod)
        self.save_backup_auth_info()

    
    def flood_within_slice(self, datapath, in_port, slice_id, msg):
        """
        Floods the given packet, ensuring that only hosts on slice
        `slice_id` will receive it. `in_port` is the port through
        which the packet has entered
        """

        # Load the switch object on which flooding is required
        switch = switch_db[datapath.id]
        actions = []

        # Add action to output to all ports on this switch on the same slice
        if slice_id in switch.slice_to_ports:
            out_ports = switch.slice_to_ports[slice_id]
            for out_port in out_ports:
                actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))

        # Add action to output to all ports on this switch on the TRUNK slice
	if TRUNK in switch.slice_to_ports:
        	out_ports = switch.slice_to_ports[TRUNK]
	else:
		out_ports = {}
        for out_port in out_ports:
            actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
        if TRUNK-1 in switch.slice_to_ports:
            out_ports = switch.slice_to_ports[TRUNK-1]
            for out_port in out_ports:
                actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))


        # Create a packet out message
        packet_out_message = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions)

        # ... and send it
        datapath.send_msg(packet_out_message)

    def add_flow(self, datapath, port, dst, actions):
        """
        Adds a flow rule on the switch represented by `datapath` that matches
        all packets entering via `port` destined for the MAC `dst`. The rule
        will apply `actions` to such packets
        """

        # Get the OpenFlow protocol instance
        ofproto = datapath.ofproto

        # Create a match rule that matches the ingress port and destination MAC
        match = datapath.ofproto_parser.OFPMatch(
            in_port=port, dl_dst=haddr_to_bin(dst))

        # Create a flow mod message
        flow_mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        # ... and send it
        datapath.send_msg(flow_mod)

    def del_flow(self, datapath, port, dst, actions):
        """
        Deletes any flow rule on the switch represented by `datapath` that matches
        all packets entering via `port` destined for the MAC `dst`.
        """

        # Get the OpenFlow protocol instance
        ofproto = datapath.ofproto

        # Create a match rule that matches ingress port and destination MAC
        match = datapath.ofproto_parser.OFPMatch(
            in_port=port, dl_dst=haddr_to_bin(dst))

        # Create a flow mod message
        flow_mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        # ... and send it
        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        The packet in handler. Gets called whenever a Packet-In OpenFlow
        message is received on any switch
        """
        # Retrieve attributes from the packet in message
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.in_port
        dpid = datapath.id
        switch = switch_db[dpid]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
	
	if allow_preauth == True:
	    try:
		pre_auth_list = open('preauthenticated_mac.json','r')
		global preauthenticated_mac
		preauthenticated_mac = json.load(pre_auth_list)
       		pre_auth_list.close()
	    except:
		print "Error loading preauthenticated MAC adresses"


	if src in preauthenticated_mac:
                print("Preauthenticated host noted",src)
                slice_id = AUTHENTICATED_SLICE
                switch.port_to_slice[in_port] = AUTHENTICATED_SLICE
                mac_to_slice[src] = AUTHENTICATED_SLICE
                if slice_id not in switch.slice_to_ports:
                    switch.slice_to_ports[slice_id] = []
                switch.slice_to_ports[slice_id].append(in_port);
                mac_port_authenticated[src] = None
	

        # Assign a default slice ID to the port if none has been configured in the config file
        if in_port not in switch.port_to_slice:
             	self.logger.warn("Slice id not found")
                slice_id = self.unauth_slice
                self.unauth_slice = self.unauth_slice + 1
                print("unauth slice increment",self.unauth_slice)
                switch.port_to_slice[in_port] = slice_id
                mac_to_slice[src] = slice_id
                if slice_id not in switch.slice_to_ports:
                    switch.slice_to_ports[slice_id] = []
                switch.slice_to_ports[slice_id].append(in_port);
        slice_id = switch.port_to_slice[in_port]

        # If the packet has entered through a trunk port, then get its slice ID from its source MAC
        # Else note that the source MAC belongs to the slice that `in_port` is configured on
        if slice_id == TRUNK:
            if src in mac_to_slice:
                slice_id = mac_to_slice[src]
            else:
                slice_id = UNTRUSTED_SLICE
        elif slice_id == UNTRUSTED_SLICE:
                if src in mac_port_authenticated:
                        slice_id = AUTHENTICATED_SLICE
                        print ('authenticated mac')
                else:
                        slice_id = UNTRUSTED_SLICE
                        mac_to_slice[src] = UNTRUSTED_SLICE
                cisco_mac[src] = None
        elif src not in mac_to_slice:
            mac_to_slice[src] = slice_id

        # Add this MAC to the switching table of the concerned switch
        switch.dest_mac_to_port[src] = in_port

        if dst in switch.dest_mac_to_port:
            # If we already know through which port the target MAC is reachable, add a flow rule
            out_port = switch.dest_mac_to_port[dst]
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, in_port, dst, actions)
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions)
            datapath.send_msg(out)
        else:
            # Discover the target MAC's location by flooding on the relevant slice
            self.flood_within_slice(datapath, in_port, slice_id, msg)
        self.save_backup_ports_and_slice()
        self.save_backup_auth_info()

    def handle_port_modify(self,ev):
        msg = ev.msg
        if msg.desc.state != 1:
                return
        print 'Port Down'
        datapath = msg.datapath
        dpid = datapath.id
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        switch = switch_db[dpid];
        for mac in switch.dest_mac_to_port:
            port = switch.dest_mac_to_port[mac]
            if port == port_no:
                for dpid1 in switch_db.keys():
                    datapath = self.dpset.get(dpid1)
                    ofproto = datapath.ofproto

                    match = datapath.ofproto_parser.OFPMatch(dl_dst=haddr_to_bin(mac))

                    flow_mod = datapath.ofproto_parser.OFPFlowMod(
                        datapath=datapath, match=match, cookie=0,
                        command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0,
                        priority=ofproto.OFP_DEFAULT_PRIORITY,
                        flags=ofproto.OFPFF_SEND_FLOW_REM)

                    datapath.send_msg(flow_mod)
                
                datapath = self.dpset.get(dpid)
                match = datapath.ofproto_parser.OFPMatch(in_port=port)

                flow_mod = datapath.ofproto_parser.OFPFlowMod(
                    datapath=datapath, match=match, cookie=0,
                    command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0,
                    priority=ofproto.OFP_DEFAULT_PRIORITY,
                    flags=ofproto.OFPFF_SEND_FLOW_REM)

                datapath.send_msg(flow_mod)
                if mac in mac_to_slice:
                        if mac_to_slice[mac] == AUTHENTICATED_SLICE:
                                mac_to_slice[mac] = self.unauth_slice

        if switch.port_to_slice[port_no] == AUTHENTICATED_SLICE:
            switch.port_to_slice[port_no] = self.unauth_slice
            switch.slice_to_ports[self.unauth_slice]=[port_no]
            self.unauth_slice += 1
            
            switch.slice_to_ports[AUTHENTICATED_SLICE].remove(port_no)
        self.save_backup_ports_and_slice()
        self.save_backup_auth_info()



    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        print(ev.__dict__)
        print(ev.msg.__dict__)
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
            self.handle_port_modify(ev)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
