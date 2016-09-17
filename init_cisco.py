import subprocess

def init(authserver_mac):
  script = '''
  spawn ssh sdn@192.168.9.9
  expect \"Password: \"
  send \"SDN123\\r\"
  expect \"#\"
  send \"conf t\\r\"
  expect \"#\"
  send \"no mac access-list extended unauth\\r\"
  expect \"#\"
  send \"mac access-list extended unauth\\r\"
  expect \"#\"
  send \"permit any host {0}\\r\"
  expect \"#\"
  send \"permit any host ffff.ffff.ffff\\r\"
  expect \"#\"
  send \"exit\\r\"
  expect \"#\"
  send \"interface range GigabitEthernet 0/1-20\\r\"
  expect \"#\"
  send \"mac access-group unauth in\\r\"
  expect \"#\"
  send \"exit\\r\"
  expect \"#\"
  send \"exit\\\r"
  expect \"#\"
  send \"write memory\\r\"
  expect \"#\"
  send \"exit\\r\"
  expect eof
  '''
  
  p1 = subprocess.Popen(['/usr/bin/expect'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
  p1.stdin.write(script.format(authserver_mac))
  print p1.communicate()
  p1.stdin.close()

