import subprocess

def get_mac_from_arp(ip):
    p1 = subprocess.Popen(['/usr/sbin/arp','-an',ip],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    out = p1.communicate()[0]
    parsed = out.split()
    mac_addr = parsed[3]
    return mac_addr

def cisco_format(mac_addr):
    cisco_format = mac_addr[0:2]+mac_addr[3:5]+'.'+mac_addr[6:8]+mac_addr[9:11]+'.'+mac_addr[12:14]+mac_addr[15:17]
    return cisco_format

def get_cisco_port(mac):
    script = '''
    spawn ssh sdn@192.168.9.9
    expect \"Password: \"
    send \"SDN123\\r\"
    expect \"#\"
    send \"show mac address-table address {0}\\r\"
    expect \"#\"
    send \"exit\\r\"
    expect eof
    '''

    p1 = subprocess.Popen(['/usr/bin/expect'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    p1.stdin.write(script.format(mac))
    output = p1.communicate()[0]
    p1.stdin.close()
    line_separated = output.split('\n')
    for line in line_separated:
        if mac in line and 'Gi' in line:
            parsed = line.split('Gi0/')[1]
            return int(parsed)

    return -1

def authenticate(port,mac):
	script = '''
	spawn ssh sdn@192.168.9.9
	expect \"Password: \"
	send \"SDN123\\r\"
	expect \"#\"
	send \"conf t\\r\"
	expect \"#\"
	send \"no mac access-list extended authint{0}\\r\"
	expect \"#\"
	send \"mac access-list extended authint{0}\\r\"
	expect \"#\"
	send \"permit host {1} any\\r\"
	expect \"#\"
	send \"exit\\r\"
	send \"interface GigabitEthernet0/{0}\\r\"
	expect \"#\"
	send \"no mac access-group unauth\\r\"
	expect \"#\"
	send \"mac access-group authint{0} in\\r\"
	expect \"#\"
	send \"exit\\r\"
	expect \"#\"
	send \"exit\\r\"
	expect \"#\"
	send \"write memory\\r\"
	expect \"#\"
	send \"exit\\r\"
	expect eof
	'''
	#print script.format(port,mac)
	p1 = subprocess.Popen(['/usr/bin/expect'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
	p1.stdin.write(script.format(port,mac))
	print p1.communicate()
	p1.stdin.close()

def deauthenticate(port,mac):
	script = '''
	spawn ssh sdn@192.168.9.9
	expect \"Password: \"
	send \"SDN123\\r\"
	expect \"#\"
	send \"conf t\\r\"
	expect \"#\"
	send \"no mac access-list extended authint{0}\\r\"
	expect \"#\"
	send \"interface GigabitEthernet0/{0}\\r\"
	expect \"#\"
	send \"no mac access-group authint{0} in\\r\"
	expect \"#\"
	send \"mac access-group unauth in\\r\"
	expect \"#\"
	send \"exit\\r\"
	expect \"#\"
	send \"exit\\r\"
	expect \"#\"
	send \"write memory\\r\"
	expect \"#\"
	send \"exit\\r\"
	expect eof
	'''
	print script.format(port,mac)
	p1 = subprocess.Popen(['/usr/bin/expect'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
	p1.stdin.write(script.format(port,mac))
	print p1.communicate()
	p1.stdin.close()
