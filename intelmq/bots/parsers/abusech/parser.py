# -*- coding: utf-8 -*-
""" Single Parser for Abuse.ch feeds """

import sys

from dateutil.parser import parse as dateparser
from intelmq.lib.bot import ParserBot
from intelmq.lib.message import Event


class AbusechParserBot(ParserBot):
    lastgenerated = None

    SOURCE_FEEDS = {'https://feodotracker.abuse.ch/blocklist/?download=domainblocklist': 'Cridex',
                    'https://feodotracker.abuse.ch/blocklist/?download=ipblocklist': 'Cridex',
                    'https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist': 'Palevo',
                    'https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist': 'Palevo',
                    'https://zeustracker.abuse.ch/blocklist.php?download=baddomains': 'Zeus',
                    'https://zeustracker.abuse.ch/blocklist.php?download=badips': 'Zeus'}

    DOMAIN_FEEDS = {'https://feodotracker.abuse.ch/blocklist/?download=domainblocklist',
                    'https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist',
                    'https://zeustracker.abuse.ch/blocklist.php?download=baddomains'}

    IP_FEEDS = {'https://feodotracker.abuse.ch/blocklist/?download=ipblocklist',
                'https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist',
                'https://zeustracker.abuse.ch/blocklist.php?download=badips'}

    RANSOMWARE_FEEDS = {'https://ransomwaretracker.abuse.ch/feeds/csv/'}

    def parse_line(self, line, report):
        if line.startswith('#') or len(line) == 0:
            self.tempdata.append(line)

            if 'Generated on' in line:
                row = line.strip('# ')[13:]
                self.lastgenerated = dateparser(row).isoformat()

        else:
            event = Event(report)
            if report['feed.url'] in AbusechParserBot.DOMAIN_FEEDS:
                event.add('time.source', self.lastgenerated)
                event.add('classification.type', 'c&c')
                event.add('source.fqdn', line)
                event.add('raw', line)
                event.add('malware.name', AbusechParserBot.SOURCE_FEEDS[report['feed.url']])

            if report['feed.url'] in AbusechParserBot.IP_FEEDS:
                event.add('time.source', self.lastgenerated)
                event.add('classification.type', 'c&c')
                event.add('source.ip', line)
                event.add('raw', line)
                event.add('malware.name', AbusechParserBot.SOURCE_FEEDS[report['feed.url']])

            if report['feed.url'] in AbusechParserBot.RANSOMWARE_FEEDS:
                value = line.split(',')
                if '|' in value[7]:
                    for ipaddr in value[7].strip('"').split('|'):
                        new_line = \
                            value[0].strip('"') + ',' + value[1].strip('"') + ',' + value[3].strip('"') \
                            + ',' + value[4].strip('"') + ',' + value[5].strip('"') + ',' + value[6].strip('"') \
                            + ',' + ipaddr + ',' + value[8].strip('"') + ',' + value[9].strip('"')

                        value = new_line.split(',')
                        event.add('classification.identifier', value[2].lower())
                        event.add('classification.type', 'c&c')
                        event.add('time.source', value[0] + ' UTC', force=True)
                        event.add('status', value[5])
                        event.add('source.ip', value[7])
                        event.add('raw', line)
                        if FQDN.is_valid(value[3]):
                            event.add('source.fqdn', value[3])
                        if URL.is_valid(value[4]):
                            event.add('source.url', value[4])
                else:
                    event.add('classification.identifier', value[2].lower())
                    event.add('classification.type', 'c&c')
                    event.add('time.source', value[0] + ' UTC')
                    event.add('status', value[5])
                    event.add('raw', line)
                    if IPAddress.is_valid(value[7]):
                        event.add('source.ip', value[7])
                    if FQDN.is_valid(value[3]):
                        event.add('source.fqdn', value[3])
                    if URL.is_valid(value[4]):
                        event.add('source.url', value[4])

        yield event

if __name__ == '__main__':
    bot = AbusechParserBot(sys.argv[1])
    bot.start()
