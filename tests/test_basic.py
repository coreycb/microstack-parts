#!/usr/bin/env python
"""
basic_test.py

This is a basic test of microstack functionality. We verify that:

1) We can install the snap.
2) We can launch a cirros image.
3) Horizon is running, and we can hit the landing page.
4) We can login to Horizon successfully.

The Horizon testing bits were are based on code generated by the Selinum
Web IDE.

"""

import os
import sys
import time
import unittest

sys.path.append(os.getcwd())

from tests.framework import Framework, check, check_output, call  # noqa E402


class TestBasics(Framework):

    def test_basics(self):
        """Basic test

        Install microstack, and verify that we can launch a machine and
        open the Horizon GUI.

        """
        host = self.get_host()
        host.install()
        host.init()
        prefix = host.prefix

        endpoints = check_output(
            *prefix, '/snap/bin/microstack.openstack', 'endpoint', 'list')

        # Endpoints should be listening on 10.20.20.1
        self.assertTrue("10.20.20.1" in endpoints)

        # Endpoints should not contain localhost
        self.assertFalse("localhost" in endpoints)

        # We should be able to launch an instance
        print("Testing microstack.launch ...")
        check(*prefix, '/snap/bin/microstack.launch', 'cirros',
              '--name', 'breakfast', '--retry')

        # ... and ping it
        # Skip these tests in the gate, as they are not reliable there.
        # TODO: fix these in the gate!
        if 'multipass' in prefix:
            self.verify_instance_networking(host, 'breakfast')
        else:
            # Artificial wait, to allow for stuff to settle for the GUI test.
            # TODO: get rid of this, when we drop the ping tests back int.
            time.sleep(10)

        # The Horizon Dashboard should function
        self.verify_gui(host)

        self.passed = True


if __name__ == '__main__':
    # Run our tests, ignoring deprecation warnings and warnings about
    # unclosed sockets. (TODO: setup a selenium server so that we can
    # move from PhantomJS, which is deprecated, to to Selenium headless.)
    unittest.main(warnings='ignore')
