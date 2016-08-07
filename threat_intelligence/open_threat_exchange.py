#import time
#import os
import json
import requests

import threat_intelligence
from helper import Helper

class OpenThreatExchange(threat_intelligence.ThreatIntelligence):
    
    def __init__(self, configuration):
        self.key = configuration['key']

    def header(self):
        print "-\nOpenThreatExchange"

    def ip(self, ip):
        self.header()

        section = 'general'
        url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/%s/%s' % (ip, section)
        headers = {'X-OTX-API-KEY': self.key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            response_dict = json.loads(response.text)
            #Helper.prettyprint(response_dict)
            print "\t%s" % (response_dict['asn'])
        
        section = 'reputation'
        url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/%s/%s' % (ip, section)
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            response_dict = json.loads(response.text)
            #Helper.prettyprint(response_dict)
            print "\tReputation: %s" % (response_dict['reputation'])
        
        section = 'malware'
        url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/%s/%s' % (ip, section)
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            response_dict = json.loads(response.text)
            #Helper.prettyprint(response_dict)
            if response_dict['response_code'] == 0:
                print "\t%s malware sample relating to this IP found" % response_dict['size']
            else:
                print "\t0 malware sample relating to this IP found"
        
        section = 'url_list'
        url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/%s/%s' % (ip, section)
        response = requests.get(url, headers=headers)
        response_dict = json.loads(response.text)
        #Helper.prettyprint(response_dict)
        if response.status_code == 200:
            print "\t%d URLs hosted on this IP and linked to malware" % (response_dict['actual_size'])

    def domain(self, domain):
        self.header()

        section = 'general'
        url = 'https://otx.alienvault.com/api/v1/indicators/domain/%s/%s' % (domain, section)
        headers = {'X-OTX-API-KEY': self.key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            response_dict = json.loads(response.text)
            #Helper.prettyprint(response_dict)
            print "\t%s pulse found" % (response_dict['pulse_info']['count'])
            print "\tAlexa: %s" % (response_dict['alexa'])
            print "\tWhois: %s" % (response_dict['whois'])
        else:
            logger.error("failed %s" % response.text)

        section = 'malware'
        url = 'https://otx.alienvault.com/api/v1/indicators/domain/%s/%s' % (domain, section)
        headers = {'X-OTX-API-KEY': self.key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            response_dict = json.loads(response.text)
            #Helper.prettyprint(response_dict)
            print "\tMalware: %s" % (response_dict['result'])

    def hash(self, hash):
        self.header()

        section = 'general'
        url = 'https://otx.alienvault.com/api/v1/indicators/file/%s/%s' % (hash, section)
        headers = {'X-OTX-API-KEY': self.key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            response_dict = json.loads(response.text)
            #Helper.prettyprint(response_dict)
            print "\tIndicator: %s" % (response_dict['indicator'])
            print "\t%s pulse found" % (response_dict['pulse_info']['count'])
        else:
            logger.error("failed %s" % response.text)

        section = 'analysis'
        url = 'https://otx.alienvault.com/api/v1/indicators/file/%s/%s' % (hash, section)
        headers = {'X-OTX-API-KEY': self.key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            response_dict = json.loads(response.text)
            #Helper.prettyprint(response_dict)
            print "\tAnalysis: %s" % (response_dict['analysis'])
            print "\tMalware:  %s" % (response_dict['malware'])
        else:
            logger.error("failed %s" % response.text)

    def file(self, filename):
        self.header()
        sha256 = Helper.sha256(filename)
        print "\tOTX does not support file upload, checking SHA-256 hash instead"
        self.hash(sha256)
