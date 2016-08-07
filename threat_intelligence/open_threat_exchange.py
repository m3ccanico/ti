#import time
#import os
import json
import requests

import threat_intelligence
from helper import Helper

class OpenThreatExchange(threat_intelligence.ThreatIntelligence):
    
    def __init__(self, configuration, arguments):
        self.key = configuration['key']

    def header(self, additional=''):
        if additional:
            print "-\nOpenThreatExchange (%s)" % additional
        else:
            print "-\nOpenThreatExchange"

    def ip(self, ip):
        self.header('https://otx.alienvault.com/indicator/ip/%s/' % ip)
        
        section = 'general'
        url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/%s/%s' % (ip, section)
        headers = {'X-OTX-API-KEY': self.key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            response_dict = json.loads(response.text)
            #Helper.prettyprint(response_dict)
            if 'asn' in response_dict:
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
        self.header('https://otx.alienvault.com/indicator/domain/%s/' % domain)
        
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
        self.header('https://otx.alienvault.com/indicator/file/%s/' % hash)
        
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
            if 'analysis' in response_dict and response_dict['analysis']:
                print "\tAnalysis is available"
            if 'malware' in response_dict and response_dict['malware']:
                print "\tMalware information available"
        else:
            logger.error("failed %s" % response.text)

    def file(self, filename):
        self.header()
        sha256 = Helper.sha256(filename)
        print "\tOTX does not support file upload, checking SHA-256 hash instead"
        self.hash(sha256)

    def url(self, url):
        self.header('https://otx.alienvault.com/indicator/url/%s/' % url)
        
        section = 'general'
        url = 'https://otx.alienvault.com/api/v1/indicators/url/%s/%s' % (url, section)
        headers = {'X-OTX-API-KEY': self.key}
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            response_dict = json.loads(response.text)
            #Helper.prettyprint(response_dict)
            print "\t%s pulse found" % (response_dict['pulse_info']['count'])
        else:
            logger.error("failed %s" % response.text)
        
        section = 'url_list'
        url = 'https://otx.alienvault.com/api/v1/indicators/url/%s/%s' % (url, section)
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            response_dict = json.loads(response.text)
            if 'country_name' in response_dict:
                print "\tCountry: %s" % response_dict['country_name']
            if 'city' in response_dict:
                print "\tCity:    %s" % response_dict['city']
            if 'latitude' in response_dict and 'longitude' in response_dict:
                print "\tMap:     http://maps.google.com/maps?z=5&t=m&q=loc:%s+%s" % \
                    (response_dict['latitude'], response_dict['longitude'])
            #Helper.prettyprint(response_dict)
            #print "\tIndicator: %s" % (response_dict['indicator'])
            #print "\t%s pulse found" % (response_dict['pulse_info']['count'])
        else:
            logger.error("failed %s" % response.text)
