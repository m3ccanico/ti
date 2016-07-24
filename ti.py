#!/usr/bin/python


#import getopt
import argparse
import sys

import thread_intelligence

def main(argv):
    
    
    parser = argparse.ArgumentParser(description='Looks up thread intelligence from various sources.')
    parser.add_argument('-c', '--config', default='providers.yml', metavar='FILE', type=file, help='configuration file, default providers.yml')
    parser.add_argument('value', type=str, help='a value to lookup')
    args = parser.parse_args()
    
    print args
    
    #thread_intelligence.ThreadIntelligence.parse_providers('')
        
    key = '65b82ca4cb5d6d9defc3a8034fb6696e1f098b725a362bdefd9be6c8079b040e'
    provider = thread_intelligence.VirusTotal(key)
    #provider.hash(args.value)


if __name__ == "__main__":
    main(sys.argv)
