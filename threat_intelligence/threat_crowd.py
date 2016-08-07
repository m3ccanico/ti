import time
import os
import json
import requests
import logging

import threat_intelligence
from helper import Helper

class ThreatCrowd(threat_intelligence.ThreatIntelligence):
    
    def __init__(self, arguments):
        
        self.ts_file = os.path.join('.cache', 'threatcrowd')
        
        # check if caching file exists
        if os.path.isfile(self.ts_file):
            # read file
            file = open(self.ts_file, 'r')
            self.ts = file.read().strip()
            file.close
            
            # check ts
            try:
                self.ts = float(self.ts)
            except ValueError:
                self.ts = time.time()
        else:
            # create cache dir if it does not exists yet
            if not os.path.isdir('.cache'):
                os.makedirs('.cache')
            
            # creat ts file with current timestamp
            self.ts = time.time()
            file = open(self.ts_file, 'w')
            file.write(self.ts)
            file.close
                
        #self.vt = threat_crowd.ThreatCrowd(configuration['key'])
        #self.key = configuration['key']

    def header(self, additional=''):
        if additional:
            print "-\nThreatCrowd (%s)" % additional
        else:
            print "-\nThreatCrowd"

    def ip(self, ip):
        self.check_timeout()
        
        url = 'https://www.threatcrowd.org/searchApi/v2/ip/report/'
        parameters = {'ip': ip}
        response = requests.get(url, params=parameters)
        response_dict = json.loads(response.text)
        #Helper.prettyprint(response_dict)
        
        if int(response_dict['response_code']) == 1:
            self.header(response_dict['permalink'])
            if 'resolutions' in response_dict: 
                print "\t%i domains resolve to this ip" % len(response_dict['resolutions'])
            if 'hashes' in response_dict: 
                print "\t%i malicious files referring to this IP address" % len(response_dict['hashes'])
            if 'references' in response_dict: 
                print "\t%i references for this IP address" % len(response_dict['references'])
        else:
            logging.error("unknown response code: >%s<" % response_dict['response_code'])
        
        self.update_ts()

    def domain(self, domain):
        self.check_timeout()
        
        url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/'
        parameters = {'domain': domain}
        response = requests.get(url, params=parameters)
        response_dict = json.loads(response.text)
        #Helper.prettyprint(response_dict)
        
        if int(response_dict['response_code']) == 1:
            self.header(response_dict['permalink'])
            #print "\tCategories: %s" % ', '.join(response_dict['categories'])
            ips = (resolution['ip_address'] for resolution in response_dict['resolutions'])
            print "\tResolved IPs: %s" % ', '.join(ips)
            if 'hashes' in response_dict: 
                print "\t%i hashes linked to this domain" % len(response_dict['hashes'])
            if 'emails' in response_dict: 
                print "\t%i emails linked to this domain" % len(response_dict['emails'])
            if 'subdomains' in response_dict: 
                print "\t%i subdomains linked this domain" % len(response_dict['subdomains'])
            if 'references' in response_dict: 
                print "\t%i references for this domain" % len(response_dict['references'])
        elif int(response_dict['response_code']) == 0:
            print "\t%s" % response_dict['verbose_msg']
        else:
            logging.error("unknown response code: %s" % response_dict['response_code'])

        self.update_ts()

    def hash(self, hash):
        self.check_timeout()
        
        url = 'https://www.threatcrowd.org/searchApi/v2/file/report/'
        parameters = {'resource': hash}
        response = requests.get(url, params=parameters)
        response_dict = json.loads(response.text)
        #Helper.prettyprint(response_dict)
        
        if int(response_dict['response_code']) == 1:
            self.header(response_dict['permalink'])
            if 'md5' in response_dict: 
                print "\tMD5:       %s" % response_dict['md5']
            if 'sha1' in response_dict:  
                print "\tSHA1:      %s" % response_dict['sha1']
            if 'scans' in response_dict: 
                print "\tConsidered malicious by %s scanners" % len(response_dict['scans'])
            if 'ips' in response_dict: 
                print "\t%i IPs linked this hash" % len(response_dict['ips'])
            if 'domains' in response_dict: 
                print "\t%i domains linked this hash" % len(response_dict['domains'])
            if 'references' in response_dict: 
                print "\t%i references for this hash" % len(response_dict['references'])
        elif int(response_dict['response_code']) == 0:
            print "\tunknown hash"
        else:
            logging.error("unknown response code: %s" % response_dict['response_code'])
        
        self.update_ts()

    def email(self, email):
        self.check_timeout()
        
        url = 'https://www.threatcrowd.org/searchApi/v2/email/report/'
        parameters = {'email': email}
        response = requests.get(url, params=parameters)
        response_dict = json.loads(response.text)
        #Helper.prettyprint(response_dict)
        
        if int(response_dict['response_code']) == 1:
            self.header(response_dict['permalink'])
            #if 'ips' in response_dict: print "\t%i IPs linked this hash" % len(response_dict['ips'])
            if 'domains' in response_dict: 
                print "\t%i domains linked this email" % len(response_dict['domains'])
            if 'references' in response_dict: 
                print "\t%i references for this email" % len(response_dict['references'])
        elif int(response_dict['response_code']) == 0:
            print "\tunknown email"
        else:
            logging.error("unknown response code: %s" % response_dict['response_code'])
        
        self.update_ts()
    
    def update_ts(self):
        # create cache dir if it does not exists yet
        if not os.path.isdir('.cache'):
            os.makedirs('.cache')
        
        # creat ts file with current timestamp
        self.ts = time.time()
        file = open(self.ts_file, 'w')
        file.write(str(self.ts))
        file.close
        #print "updated ts"
    
    def check_timeout(self):
        delta = time.time() - self.ts
        if delta < 10:
            #print "sleep:", str(15-delta)
            logging.debug('wait %d seconds for timeout' % (10-delta))
            time.sleep(10-delta)
            