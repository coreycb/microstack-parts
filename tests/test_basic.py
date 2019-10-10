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

import json
import os
import sys
import time
import unittest
import xvfbwrapper
from selenium import webdriver
from selenium.webdriver.common.by import By

sys.path.append(os.getcwd())

from tests.framework import Framework, check, check_output, call  # noqa E402


class TestBasics(Framework):

    def setUp(self):
        super(TestBasics, self).setUp()
        # Setup Selenium Driver
        self.display = xvfbwrapper.Xvfb(width=1280, height=720)
        self.display.start()
        self.driver = webdriver.PhantomJS()

    def tearDown(self):
        # Tear down selenium driver
        self.driver.quit()
        self.display.stop()

        super(TestBasics, self).tearDown()

    def test_basics(self):
        """Basic test

        Install microstack, and verify that we can launch a machine and
        open the Horizon GUI.

        """
        launch = '/snap/bin/microstack.launch'
        openstack = '/snap/bin/microstack.openstack'

        print("Testing microstack.launch ...")

        check(*self.PREFIX, launch, 'cirros', '--name', 'breakfast',
              '--retry')

        endpoints = check_output(
            *self.PREFIX, '/snap/bin/microstack.openstack', 'endpoint', 'list')

        # Endpoints should be listening on 10.20.20.1
        self.assertTrue("10.20.20.1" in endpoints)

        # Endpoints should not contain localhost
        self.assertFalse("localhost" in endpoints)

        # Verify that microstack.launch completed successfully

        # Ping the instance
        ip = None
        servers = check_output(*self.PREFIX, openstack,
                               'server', 'list', '--format', 'json')
        servers = json.loads(servers)
        for server in servers:
            if server['Name'] == 'breakfast':
                ip = server['Networks'].split(",")[1].strip()
                break

        self.assertTrue(ip)

        pings = 1
        max_pings = 600  # ~10 minutes!
        while not call(*self.PREFIX, 'ping', '-c1', '-w1', ip):
            pings += 1
            if pings > max_pings:
                self.assertFalse(True, msg='Max pings reached!')

        print("Testing instances' ability to connect to the Internet")
        # Test Internet connectivity
        attempts = 1
        max_attempts = 300  # ~10 minutes!
        username = check_output(*self.PREFIX, 'whoami')

        while not call(
                *self.PREFIX,
                'ssh',
                '-oStrictHostKeyChecking=no',
                '-i', '/home/{}/.ssh/id_microstack'.format(username),
                'cirros@{}'.format(ip),
                '--', 'ping', '-c1', '91.189.94.250'):
            attempts += 1
            if attempts > max_attempts:
                self.assertFalse(True, msg='Unable to access the Internet!')
            time.sleep(1)

        if 'multipass' in self.PREFIX:
            print("Opening {}:80 up to the outside world".format(
                self.HORIZON_IP))

            with open('/tmp/_10_hosts.py', 'w') as hosts:
                hosts.write("""\
# Allow all hosts to connect to this machine
ALLOWED_HOSTS = ['*',]
""")
            check('multipass', 'copy-files', '/tmp/_10_hosts.py',
                  '{}:/tmp/_10_hosts.py'.format(self.MACHINE))
            check(
                *self.PREFIX, 'sudo', 'cp', '/tmp/_10_hosts.py',
                '/var/snap/microstack/common/etc/horizon/local_settings.d/'
            )
            check(*self.PREFIX, 'sudo', 'snap', 'restart', 'microstack')

        print('Verifying GUI for (IP: {})'.format(self.HORIZON_IP))
        # Verify that our GUI is working properly
        self.driver.get("http://{}/".format(self.HORIZON_IP))
        # Login to horizon!
        self.driver.find_element(By.ID, "id_username").click()
        self.driver.find_element(By.ID, "id_username").send_keys("admin")
        self.driver.find_element(By.ID, "id_password").send_keys("keystone")
        self.driver.find_element(By.CSS_SELECTOR, "#loginBtn > span").click()
        # Verify that we can click something on the dashboard -- e.g.,
        # we're still not sitting at the login screen.
        self.driver.find_element(By.LINK_TEXT, "Images").click()

        self.passed = True


if __name__ == '__main__':
    # Run our tests, ignoring deprecation warnings and warnings about
    # unclosed sockets. (TODO: setup a selenium server so that we can
    # move from PhantomJS, which is deprecated, to to Selenium headless.)
    unittest.main(warnings='ignore')
