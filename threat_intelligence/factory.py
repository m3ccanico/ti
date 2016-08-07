import virus_total
import malwr
import open_threat_exchange
import threat_crowd

class Factory:
    @classmethod
    def parse_providers(cls, cfg):
        providers = []
        #print cfg
        for provider_cfg in cfg['providers']:
            #print provider_cfg
            if 'virustotal' in provider_cfg:
                providers.append(virus_total.VirusTotal(provider_cfg['virustotal']))
            elif 'threatcrowd' in provider_cfg:
                providers.append(threat_crowd.ThreatCrowd())
            elif 'malwr' in provider_cfg:
                providers.append(malwr.Malwr(provider_cfg['malwr']))
            elif 'otx' in provider_cfg:
                providers.append(open_threat_exchange.OpenThreatExchange(provider_cfg['otx']))
                #print "virus"
        return providers
        #if 'virustotal' in cfg['providers']:
        #    print "virus"