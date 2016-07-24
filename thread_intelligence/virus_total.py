import time
import virustotal
import os

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
                
        self.vt = virustotal.VirusTotal(configuration['key'])
    
    def ip(self, ip):
        self.check_timeout()
        report = self.vt.get(ip)
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
            time.sleep(15-delta)
            