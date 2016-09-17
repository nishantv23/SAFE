import subprocess,re

class Monitor:

    def __init__(self,callback):
        self.callback=callback

    def start(self):
        prog=re.compile('.* on Interface GigabitEthernet0/([0-9][0-9]?), changed state to down.*')
        process=subprocess.Popen(['expect','-f','expect'],stdout=subprocess.PIPE)

        while True:
            for line in iter(process.stdout.readline, ''):
                print line
                match= prog.match(line)
                if match:
                    self.callback(int(match.group(1)))

