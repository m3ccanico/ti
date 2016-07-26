#import time
#import os
import json
import requests

import thread_intelligence

class OpenThreadExchange(thread_intelligence.ThreadIntelligence):
    
    def __init__(self, configuration):
        self.key = configuration['key']

    def header(self):
        print "OpenThreadExchange"

    def ip(self, ip):
        section = 'general'
        url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/%s/%s' % (ip, section)
        headers = {'X-OTX-API-KEY': self.key}
        response = requests.get(url, headers=headers)
        response_dict = json.loads(response.text)
        if response.status_code == 200:
            self.header()
            print "\tASN %s" % (response_dict['asn'])
        
        section = 'reputation'
        url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/%s/%s' % (ip, section)
        headers = {'X-OTX-API-KEY': self.key}
        response = requests.get(url, headers=headers)
        response_dict = json.loads(response.text)
        import pprint
        pp = pprint.PrettyPrinter(indent=2)
        #pp.pprint(response_dict)
        if response.status_code == 200:
            print "\tReputation: %s" % (response_dict['reputation'])
        
        section = 'malware'
        url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/%s/%s' % (ip, section)
        headers = {'X-OTX-API-KEY': self.key}
        response = requests.get(url, headers=headers)
        response_dict = json.loads(response.text)
        #pp.pprint(response_dict)
        if response.status_code == 200:
            if response_dict['response_code'] == 0:
                print "\t%d malware sample relating to this IP found" % response_dict['1183446']
            else:
                print "\t0 malware sample relating to this IP found"
        
        section = 'url_list'
        url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/%s/%s' % (ip, section)
        headers = {'X-OTX-API-KEY': self.key}
        response = requests.get(url, headers=headers)
        response_dict = json.loads(response.text)
        #pp.pprint(response_dict)
        if response.status_code == 200:
            print "\t%d URLs hosted on this IP and linked to malware" % (response_dict['actual_size'])
