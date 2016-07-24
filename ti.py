#!/usr/bin/env python


#import getopt
import argparse
import sys
import yaml

import thread_intelligence

def main(argv):
    
    # parse command line arguments
    parser = argparse.ArgumentParser(description='Looks up thread intelligence from various sources.')
    parser.add_argument('-c', '--config', default='providers.yml', metavar='FILE', type=file, help='configuration file, default providers.yml')
    parser.add_argument('value', type=str, help='a value to lookup')
    args = parser.parse_args()
    #print args
    
    # parse configuration file
    cfg = yaml.load(args.config)
    
    providers = thread_intelligence.Factory.parse_providers(cfg)
    
    for provider in providers:
        pass
        provider.hash(args.value)


if __name__ == "__main__":
    main(sys.argv)
