import logging
import re
import os
import validators

class ThreatIntelligence():
    
    TYPE_NONE = 'none'
    TYPE_HASH = 'hash'
    TYPE_DOMAIN = 'domain'
    TYPE_IP = 'ip'
    TYPE_FILE = 'file'
    TYPE_EMAIL = 'email'
    TYPE_URL = 'url'

    @classmethod
    def get_type(cls, value):
        type = ThreatIntelligence.TYPE_NONE
        # MD5
        if re.match('^[a-f0-9]{32}$', value, re.IGNORECASE):
            type = ThreatIntelligence.TYPE_HASH
            logging.debug('MD5')
        
        # SHA1
        elif re.match('^[a-f0-9]{40}$', value, re.IGNORECASE):
            type = ThreatIntelligence.TYPE_HASH
            logging.debug('SHA1')
        
        # SHA256
        elif re.match('^[a-f0-9]{64}$', value, re.IGNORECASE):
            type = ThreatIntelligence.TYPE_HASH
            logging.debug('SHA256')
        
        # IPv4
        elif validators.ipv4(value):
            type = ThreatIntelligence.TYPE_IP
            logging.debug(ThreatIntelligence.TYPE_IP)
        
        # file
        elif os.path.isfile(value):
            type = ThreatIntelligence.TYPE_FILE
            logging.debug(ThreatIntelligence.TYPE_FILE)
        
        # email
        elif validators.email(value):
            type = ThreatIntelligence.TYPE_EMAIL
            logging.debug(ThreatIntelligence.TYPE_EMAIL)
        
        # domain
        elif validators.domain(value):
            type = ThreatIntelligence.TYPE_DOMAIN
            logging.debug(ThreatIntelligence.TYPE_DOMAIN)
        
        # url
        elif validators.url(value):
            type = ThreatIntelligence.TYPE_URL
            logging.debug(ThreatIntelligence.TYPE_URL)
        
        else:
            type = ThreatIntelligence.TYPE_NONE
            raise NotImplementedError
        return type

    def __init__(self, configuration, arguments):
        pass

    def header(self):
        raise NotImplementedError

    def ip(self, ip):
        #raise NotImplementedError
        pass

    def domain(self, domain):
        #raise NotImplementedError
        pass

    def url(self, url):
        #raise NotImplementedError
        pass

    def email(self, email):
        #raise NotImplementedError
        pass

    def hash(self, hash):
        #raise NotImplementedError
        pass

    def file(self, filename):
        #raise NotImplementedError
        pass

    def url(self, url):
        #raise NotImplementedError
        pass

    def query(self, type, value):
        if type == ThreatIntelligence.TYPE_HASH:
            self.hash(value)
        elif type == ThreatIntelligence.TYPE_IP:
            self.ip(value)
        elif type == ThreatIntelligence.TYPE_DOMAIN:
            self.domain(value)
        elif type == ThreatIntelligence.TYPE_URL:
            self.url(value)
        elif type == ThreatIntelligence.TYPE_EMAIL:
            self.email(value)
        elif type == ThreatIntelligence.TYPE_FILE:
            self.file(value)
        else:
            raise NotImplementedError


