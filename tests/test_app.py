import unittest
import tempfile
import os
from datetime import datetime

from flask import request

import treestatus.app
import treestatus.model

import mock


class TestStatus(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_name = tempfile.mkstemp()

        config = {
            'sqlalchemy.url': 'sqlite:///{}'.format(self.db_name),
            'debug': True,
            'here': os.curdir,
        }
        treestatus.model.setup(config)

        self.status = treestatus.app.status
        self.status.setup(config)
        self.app = treestatus.app.app
        self.app_context = self.app.test_request_context("/").__enter__()
        treestatus.app.create_session()
        self.session = request.session

    def testLog(self):
        "Test that we can get logs in and out of the DB"
        t = datetime(2014, 10, 24, 14, 51, 00)

        with mock.patch('treestatus.app.datetime') as dt:
            dt.now.return_value = t
            dt.utcnow.return_value = t
            self.status.log('mozilla-inbound', 'me', 'closed', 'b0rken', 'infra')
            self.session.commit()

        logs = self.status.get_logs('mozilla-inbound')

        self.assertEquals(len(logs), 1)
        self.assertEquals(logs[0],
                          {'tree': u'mozilla-inbound',
                           'reason': u'b0rken',
                           'tags': u'infra',
                           'who': u'me',
                           'when': t.strftime("%Y-%m-%dT%H:%M:%S%Z"),
                           'action': u'closed',
                           })

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(self.db_name)


if __name__ == '__main__':
    unittest.main()
