#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request

DEFAULT_INTERFACE = 'wlan0'
REGEX = re.compile(r".*ESSID:\"(.*)\"")

ROOT = os.path.dirname(os.path.realpath(__file__))


def scan(interfaces):
    essids = set()
    for interface in interfaces:
        cmd = ['sudo', 'iwlist', interface, 'scanning']
        output = subprocess.check_output(cmd).decode()
        essids = essids.union(parse_scan(output))
    return essids


def parse_scan(scan_output):
    essids = set()
    for line in scan_output.splitlines():
        match = REGEX.match(line)
        if match:
            essid = match.group(1)
            if len(essid) > 0:
                essids.add(essid)
    return essids


def find_rogue(interfaces):
    essids = scan(interfaces)
    whitelist = set(Config().get_whitelist())
    rogues = essids - whitelist
    notify(rogues)


def notify(rogues):
    slack_webhooks = Config().get_slackwebhooks()
    if len(rogues) > 0:
        msg = "Found the following potentially rogue Wi-Fi SSIDs:\n" + '\n'.join(rogues)
    else:
        msg = "Found no new Wi-Fi SSIDs"

    print(msg)

    for hook in slack_webhooks:
        urllib.request.urlopen(hook, data=json.dumps({'text': msg}).encode())


def learn(interfaces):
    essids = scan(interfaces)
    config = Config()
    config.set_whitelist(essids)


class Config:
    def __init__(self):
        self.file = os.path.join(ROOT, 'config.json')

    def _get_config(self):
        if not os.path.exists(self.file):
            self._save_config({})
        return json.load(open(self.file, 'r'))

    def _save_config(self, config_obj):
        json.dump(config_obj, open(self.file, 'w'), indent=2)

    def set_whitelist(self, new_whitelist):
        obj = self._get_config()
        if 'whitelist' in obj:
            whitelist = obj['whitelist']
        else:
            whitelist = []
        whiteset = set(whitelist)
        new_whiteset = set(new_whitelist)
        new_ones = new_whitelist - whiteset
        if len(new_ones) > 0:
            print('Learned the following SSIDs:\n' + '\n'.join(new_ones))
        else:
            print('Learned no new SSIDs')
        new_combined_whitetest = whiteset.union(new_whiteset)
        obj['whitelist'] = list(new_combined_whitetest)
        self._save_config(obj)

    def get_whitelist(self):
        return self._get_config()['whitelist']

    def get_slackwebhooks(self):
        obj = self._get_config()
        if 'slack_webhooks' in obj:
            return obj['slack_webhooks']
        else:
            return []

    def get_interfaces(self):
        obj = self._get_config()
        if 'interfaces' in obj:
            return obj['interfaces']
        else:
            return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--learn', '-l', default=False, action='store_true',
                        help='take all the current SSIDs and store those in whitelist')
    args = parser.parse_args()
    config = Config()
    interfaces = config.get_interfaces()
    if len(interfaces) < 1:
        print('Must specify at least one wireless network interface in config.json')
        sys.exit(1)

    if args.learn:
        learn(interfaces)
    else:
        find_rogue(interfaces)


if __name__ == '__main__':
    main()
