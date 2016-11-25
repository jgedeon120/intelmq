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

        yield event

if __name__ == '__main__':
    bot = AbusechParserBot(sys.argv[1])
    bot.start()
