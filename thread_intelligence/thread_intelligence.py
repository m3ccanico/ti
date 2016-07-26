import logging
import re

class ThreadIntelligence():
    
    TYPE_NONE = 'none'
    TYPE_HASH = 'hash'
    TYPE_DOMAIN = 'domain'
    TYPE_IP = 'ip'

    @classmethod
    def get_type(cls, value):
        type = ThreadIntelligence.TYPE_NONE
        # MD5
        if re.match('^[a-f0-9]{32}$', value, re.IGNORECASE):
            type = ThreadIntelligence.TYPE_HASH
            logging.debug('MD5')
        # SHA1
        elif re.match('^[a-f0-9]{40}$', value, re.IGNORECASE):
            type = ThreadIntelligence.TYPE_HASH
            logging.debug('SHA1')
        # SHA256
        elif re.match('^[a-f0-9]{64}$', value, re.IGNORECASE):
            type = ThreadIntelligence.TYPE_HASH
            logging.debug('SHA256')
        # IPv4
        elif re.match('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', value):
            type = ThreadIntelligence.TYPE_IP
            logging.debug('IPv4')
        else:
            type = ThreadIntelligence.TYPE_NONE
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

    def file(self, file):
        raise NotImplementedError

    def query(self, type, value):
        if type == ThreadIntelligence.TYPE_HASH:
            self.hash(value)
        elif type == ThreadIntelligence.TYPE_IP:
            self.ip(value)
        elif type == ThreadIntelligence.TYPE_DOMAIN:
            self.domain(value)
        else:
            raise NotImplementedError


