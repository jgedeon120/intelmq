# -*- coding: utf-8 -*-
""" IntelMQ Botscout last caught bot parser """

import re
import sys

from intelmq.lib import utils
from intelmq.lib.bot import Bot
from intelmq.lib.message import Event

class BotscoutParserBot(Bot):
    """ Parser for Botscout Last Caught feed """

    def process(self):
        report = self.receive_message()

        raw_report = utils.base64_decode(report.get('raw'))
        for row in raw_report.split('</tr>'):

            '''Get Date '''
            datestamp = re.search('<!--td>([^<]+)</td-->', row)

            '''Get Bot Email'''
            botemail = re.search('<td>([^@]+@[^<]+)</td>', row)

            '''Get Source IP address'''
            botip = re.search('<td><a href=[^>]+>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</a></td>', row)

            event = Event(report)

            event.add('time.source', datestamp.group() + ' UTC-6')
            event.add('source.account', botemail.group())
            event.add('source.ip', botip.group())
            event.add('classification.type', '')
            event.add('raw', row)

            self.send_message(event)
        self.acknowledge_message()

if __name__ == '__main__':
    bot = BotscoutParserBot(sys.argv[1])
    bot.start()
