# -*- coding: utf-8 -*-

import os
import unittest

import intelmq.lib.test as test
import intelmq.lib.utils as utils

from intelmq.bots.parsers.botscout.parser import BotscoutParserBot

with open(os.path.join(os.path.dirname(__file__), 'last_caught_cache.htm')) as handle:
    EXAMPLE_FILE = handle.read()

EXAMPLE_REPORT = {'feed.name': 'botscout_last_caught',
                  'feed.url': 'http://botscout.com/last_caught_cache.htm',
                  '__type': 'Report',
                  'time.observation': '2016-11-23T06:54:15+00:00',
                  'raw': utils.base64_encode(EXAMPLE_FILE),
                  }

EXAMPLE_EVENT = {'feed.name': 'botscout_last_caught',
                 'feed.url': 'http://botscout.com/last_caught_cache.htm',
                 '__type': 'Event',
                 'time.source': '2016-11-22T16:20:00+00:00',
                 'source.account': 'ar6@emersonariel.coayako.top',
                 'source.ip': '185.103.99.60',
                 'classification.type': 'unknown',
                 'raw': '',
                 }


class TestBotscoutParserBot(test.BotTestCase, unittest.TestCase):
    """ A TestCase for BotscoutParserBot """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = BotscoutParserBot
        cls.default_input_message = EXAMPLE_REPORT

    def test_event(self):
        """ Test if correct Event has been produced """
        self.run_bot()
        self.assertMessageEqual(0, EXAMPLE_EVENT)

if __name__ == '__main__':
    unittest.main()
