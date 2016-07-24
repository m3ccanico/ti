import virustotal

import thread_intelligence

class VirusTotal(thread_intelligence.ThreadIntelligence):
    
    def __init__(self, key):
        self.vt = virustotal.VirusTotal(key)
    
    def ip(self, ip):
        report = self.vt.get(ip)
        
    def domain(self, domain):
        report = self.vt.get(domain)
    
    def hash(self, hash):
        report = self.vt.get(hash)
        
        print "Report"
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