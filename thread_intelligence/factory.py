import virus_total

class Factory:
    @classmethod
    def parse_providers(cls, cfg):
        providers = []
        #print cfg
        for provider_cfg in cfg['providers']:
            #print provider_cfg
            if 'virustotal' in provider_cfg:
                providers.append(virus_total.VirusTotal(provider_cfg['virustotal']))
                #print "virus"
        return providers
        #if 'virustotal' in cfg['providers']:
        #    print "virus"