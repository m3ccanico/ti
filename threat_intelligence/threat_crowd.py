import time
import os
import json
import requests
import logging

import threat_intelligence
from helper import Helper

class ThreatCrowd(threat_intelligence.ThreatIntelligence):
    
    def __init__(self):
        
        # check if caching file exists
        if os.path.isfile(os.path.join('.cache', 'threatcrowd')):
            # read file
            file = open(os.path.join('.cache', 'threatcrowd'), 'r')
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
            file = open(os.path.join('.cache', 'threatcrowd'), 'w')
            file.write(self.ts)
            file.close
                
        #self.vt = threat_crowd.ThreatCrowd(configuration['key'])
        #self.key = configuration['key']

    def header(self):
        print "-\nThreatCrowd"

    def ip(self, ip):
        self.check_timeout()
        
        url = 'https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=%s' % ip
        #parameters = {'ip': ip, 'apikey': self.key}
        response = requests.get(url)#, params=parameters)
        response_dict = json.loads(response.text)
        Helper.prettyprint(response_dict)
        
        if response_dict['response_code'] == 1:
            self.header()
            if 'asn' in response_dict and 'as_owner' in response_dict: print "\tASN: %s (%s)" % (response_dict['asn'], response_dict['as_owner'])
            if 'resolutions' in response_dict: print "\t%i domains resolve to this ip" % len(response_dict['resolutions'])
            if 'detected_urls' in response_dict: print "\t%i URLs hosted on this IP and linked to malware" % len(response_dict['detected_urls'])
            if 'detected_referrer_samples' in response_dict: print "\t%i malicious files referring to this IP address" % len(response_dict['detected_referrer_samples'])
            if 'detected_downloaded_samples' in response_dict: print "\t%i malicious files downloaded from this IP address" % len(response_dict['detected_downloaded_samples'])
            if 'detected_communicating_samples' in response_dict: print "\t%i maliciuos files communicating with this IP address" % len(response_dict['detected_communicating_samples'])
            if 'undetected_referrer_samples' in response_dict: print "\t%i non-malicious files referring to this IP address" % len(response_dict['undetected_referrer_samples'])
            if 'undetected_downloaded_samples' in response_dict: print "\t%i non-malicious files downloaded from this IP address" % len(response_dict['undetected_downloaded_samples'])
            if 'undetected_communicating_samples' in response_dict: print "\t%i non-maliciuos files communicating with this IP address" % len(response_dict['undetected_communicating_samples'])
        else:
            logging.error("unknown response code: %s" % response_dict['response_code'])
        
        self.update_ts()

    def domain(self, domain):
        self.check_timeout()
        
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        parameters = {'domain': domain, 'apikey': self.key}
        response = requests.get(url, params=parameters)
        response_dict = json.loads(response.text)
        #Helper.prettyprint(response_dict)

        self.header()
        if response_dict['response_code'] == 1:
            print "\tCategories: %s" % ', '.join(response_dict['categories'])
            ips = (resolution['ip_address'] for resolution in response_dict['resolutions'])
            print "\tResolved IPs: %s" % ', '.join(ips)
            if 'detected_urls' in response_dict: print "\t%i domains linked to the URL and malware" % len(response_dict['detected_urls'])
            if 'detected_referrer_samples' in response_dict: print "\t%i malicious files referring to this domain" % len(response_dict['detected_referrer_samples'])
            if 'detected_downloaded_samples' in response_dict: print "\t%i malicious files downloaded from this domain" % len(response_dict['detected_downloaded_samples'])
            if 'detected_communicating_samples' in response_dict: print "\t%i maliciuos files communicating with this domain" % len(response_dict['detected_communicating_samples'])
            if 'undetected_referrer_samples' in response_dict: print "\t%i non-malicious files referring to this domain" % len(response_dict['undetected_referrer_samples'])
            if 'undetected_downloaded_samples' in response_dict: print "\t%i non-malicious files downloaded from this domain" % len(response_dict['undetected_downloaded_samples'])
            if 'domain_siblings' in response_dict: print "\t%i domain name siblings" % len(response_dict['domain_siblings'])
        elif response_dict['response_code'] == 0:
            print "\t%s" % response_dict['verbose_msg']
        else:
            logging.error("unknown response code: %s" % response_dict['response_code'])

        self.update_ts()

    def hash(self, hash):
        self.check_timeout()
        
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        parameters = {'resource': hash, 'apikey': self.key}
        response = requests.get(url, params=parameters)
        response_dict = json.loads(response.text)
        #Helper.prettyprint(response_dict)

        self.header()
        if response_dict['response_code'] == 1:
            print "\tScan date: %s" % response_dict['scan_date']
            print "\tMD5:       %s" % response_dict['md5']
            print "\tSHA1:      %s" % response_dict['sha1']
            print "\tSHA-256:   %s" % response_dict['sha256']
            print "\tConsidered malicious by %s out of %d scanners" % (response_dict['positives'], response_dict['total'])
            scanners = (key for key, value in response_dict['scans'].iteritems())
            print "\tScanned by: %s" % ', '.join(scanners)
            pass
        elif response_dict['response_code'] == 0:
            print "\t%s" % response_dict['verbose_msg']
        else:
            logging.error("unknown response code: %s" % response_dict['response_code'])
        
        self.update_ts()

    def file(self, filename):
        self.check_timeout()
        
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        parameters = {'apikey': self.key}
        files = {'file': open(filename, 'rb')}
        response = requests.post(url, params=parameters, files=files)
        response_dict = json.loads(response.text)
        #Helper.prettyprint(response_dict)

        self.header()
        if response_dict['response_code'] == 1:
            print "\tMD5:       %s" % response_dict['md5']
            print "\tSHA1:      %s" % response_dict['sha1']
            print "\tSHA-256:   %s" % response_dict['sha256']
            print "\tSubmited for scanning check results:\n\t%s" % response_dict['permalink']
        else:
            logging.error("unknown response code: %s" % response_dict['response_code'])
        
        self.update_ts()
    
    def update_ts(self):
        # create cache dir if it does not exists yet
        if not os.path.isdir('.cache'):
            os.makedirs('.cache')
        
        # creat ts file with current timestamp
        self.ts = time.time()
        file = open('.cache/virustotal', 'w')
        file.write(str(self.ts))
        file.close
        #print "updated ts"
    
    def check_timeout(self):
        delta = time.time() - self.ts
        if delta < 10:
            #print "sleep:", str(15-delta)
            logging.debug('wait %d seconds for timeout' % (10-delta))
            time.sleep(10-delta)
            