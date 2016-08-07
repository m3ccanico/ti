import logging
import re
import os

class ThreatIntelligence():
    
    TYPE_NONE = 'none'
    TYPE_HASH = 'hash'
    TYPE_DOMAIN = 'domain'
    TYPE_IP = 'ip'
    TYPE_FILE = 'file'

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
        elif re.match('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', value):
            type = ThreatIntelligence.TYPE_IP
            logging.debug('IPv4')
        # file
        elif os.path.isfile(value):
            type = ThreatIntelligence.TYPE_FILE
            logging.debug('file')
        # domain
        elif re.match('^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', value):
            type = ThreatIntelligence.TYPE_DOMAIN
            logging.debug('domain')
        else:
            type = ThreatIntelligence.TYPE_NONE
            raise NotImplementedError
        return type

    def __init__(self, configuration):
        pass

    def header(self):
        raise NotImplementedError

    def ip(self, ip):
        raise NotImplementedError

    def domain(self, domain):
        raise NotImplementedError

    def hash(self, hash):
        raise NotImplementedError

    def file(self, filename):
        raise NotImplementedError

    def url(self, url):
        raise NotImplementedError

    def query(self, type, value):
        if type == ThreatIntelligence.TYPE_HASH:
            self.hash(value)
        elif type == ThreatIntelligence.TYPE_IP:
            self.ip(value)
        elif type == ThreatIntelligence.TYPE_DOMAIN:
            self.domain(value)
        elif type == ThreatIntelligence.TYPE_FILE:
            self.file(value)
        else:
            raise NotImplementedError


