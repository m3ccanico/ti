#!/usr/bin/env python

import argparse
import logging
import sys
import yaml

import threat_intelligence

def main(argv):
    
    # parse command line arguments
    parser = argparse.ArgumentParser(description='Looks up threat intelligence from various sources.')
    parser.add_argument('-c', '--config', default='providers.yml', metavar='FILE', type=file, help='configuration file, default providers.yml')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('value', type=str, help='a value to lookup (hash, ip, domain)')
    args = parser.parse_args()
    #print args
    
    # set up logging
    if args.debug:
        logging.basicConfig(level=logging.DEBUG,format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING,format="%(message)s")
    
    # parse configuration file
    cfg = yaml.load(args.config)
    providers = threat_intelligence.Factory.parse_providers(cfg)
    
    type = threat_intelligence.ThreatIntelligence.get_type(args.value)
    
    for provider in providers:
        provider.query(type, args.value)
        #print "p"
        #pass
        #provider.hash(args.value)


if __name__ == "__main__":
    main(sys.argv)
