#import time
#import virustotal
#import os
#import json
#import urllib

# MalwrAPI only supports submitting of samples

#from MalwrAPI import MalwrAPI

import threat_intelligence

class Malwr(threat_intelligence.ThreatIntelligence):
    
    def __init__(self, configuration, arguments):
        self.key = configuration['key']
        self.username = configuration['username']
        self.password = configuration['password']

    def header(self):
        print "Malwr"

    def ip(self, ip):
        search = "ip:%s" % ip
        res = MalwrAPI(True, self.username, self.password).search(search)
        print res
