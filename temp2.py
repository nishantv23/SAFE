import json
try:
	with open('auth_info_backup1.json') as data_f:
		data = json.load(data_f)
except IOError:
	print "Backup file not found skipping restore"



