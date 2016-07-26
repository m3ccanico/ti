#import time
#import virustotal
#import os
#import json
#import urllib

from MalwrAPI import MalwrAPI

import thread_intelligence

class Malwr(thread_intelligence.ThreadIntelligence):
    
    def __init__(self, configuration):
        self.key = configuration['key']
        self.username = configuration['username']
        self.password = configuration['password']

    def header(self):
        print "Malwr"

    def ip(self, ip):
        search = "ip:%s" % ip
        res = MalwrAPI(True, self.username, self.password).search(search)
        print res
