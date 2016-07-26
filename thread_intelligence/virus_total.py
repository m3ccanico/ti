import time
#import virustotal
import os
import json
import urllib

import thread_intelligence

class VirusTotal(thread_intelligence.ThreadIntelligence):
    
    def __init__(self, configuration):
        
        # check if caching file exists
        if os.path.isfile('.cache/virustotal'):
            # read file
            file = open('.cache/virustotal', 'r')
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
            file = open('.cache/virustotal', 'w')
            file.write(self.ts)
            file.close
                
        #self.vt = virustotal.VirusTotal(configuration['key'])
        self.key = configuration['key']

    def header(self):
        print "VirusTotal"

    def ip(self, ip):
        self.check_timeout()
        
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        parameters = {'ip': ip, 'apikey': self.key}
        response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
        #print json.dumps(response, indent=2, sort_keys=True)
        response_dict = json.loads(response)
        #import pprint
        #pp = pprint.PrettyPrinter(indent=2)
        #pp.pprint(response_dict)
        
        if response_dict['response_code'] == 1:
            self.header()
            print "\tASN %s (%s)" % (response_dict['asn'], response_dict['as_owner'])
            print "\t%i domains resolve to this ip" % len(response_dict['resolutions'])
            print "\t%i URLs hosted on this IP and linked to malware" % len(response_dict['detected_urls'])
            print "\t%i malicious files referring to this IP address" % len(response_dict['detected_referrer_samples'])
            print "\t%i malicious files downloaded from this IP address" % len(response_dict['detected_downloaded_samples'])
            print "\t%i maliciuos files communicating with this IP address" % len(response_dict['detected_communicating_samples'])
            print "\t%i non-malicious files referring to this IP address" % len(response_dict['undetected_referrer_samples'])
            print "\t%i non-malicious files downloaded from this IP address" % len(response_dict['undetected_downloaded_samples'])
            print "\t%i non-maliciuos files communicating with this IP address" % len(response_dict['undetected_communicating_samples'])
        
        self.update_ts()

    def domain(self, domain):
        self.check_timeout()
        report = self.vt.get(domain)
        self.update_ts()

    def hash(self, hash):
        self.check_timeout()
        report = self.vt.get(hash)
        
        print "VirusTotal - Report"
        print "- Resource's UID:", report.id
        print "- Scan's UID:", report.scan_id
        print "- Permalink:", report.permalink
        print "- Resource's SHA1:", report.sha1
        print "- Resource's SHA256:", report.sha256
        print "- Resource's MD5:", report.md5
        print "- Resource's status:", report.status
        print "- Antivirus' total:", report.total
        print "- Antivirus's positives:", report.positives
        for antivirus, malware in report:
            if malware:
                print
                print "Antivirus:", antivirus[0]
                print "Antivirus' version:", antivirus[1]
                print "Antivirus' update:", antivirus[2]
                print "Malware:", malware
        
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
        if delta < 15:
            #print "sleep:", str(15-delta)
            logging.debug('wait %d seconds for timeout' % (15-delta))
            time.sleep(15-delta)
            