import json

wow={1:22, 3:88, 99:17 }

f = open('new.txt','w')
f.write(json.dumps(wow))
