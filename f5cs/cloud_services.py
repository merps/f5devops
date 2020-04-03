""" Get the F5 Cloud Services configuration
Notes
-----
Set local environment variables first
"""
# export F5_SDK_USERNAME='admin'
# export F5_SDK_PWD='admin'
# export F5_SDK_CS_SUBSCRIPTION_ID=''
# export F5_SDK_LOG_LEVEL='DEBUG'

#!/usr/bin/python3
import os, sys, json
import argparse, getpass
from f5sdk.cloud_services import ManagementClient
from f5sdk.cloud_services.subscriptions import SubscriptionClient
# from f5sdk.logger import Logger
# from netaddr import *

class F5aaSSession(object):
    def __init__(self):
        self._username = None
        self._password = None
        self._subscription_id = None
        self._args = None

    def parse_args(self):
        parser = argparse.ArgumentParser(description="command line client")
        subparsers = parser.add_subparsers(dest='command', metavar='command')
        subparsers.required = True
        parser.set_defaults(funct=self.argparser_handler)

        # Login
        sub_parser = subparsers.add_parser("login", help="Login with email and password")
        sub_parser.add_argument('-u', dest='user', help='user.  If this argument is not passed it will be requested.')
        sub_parser.add_argument('-p', dest='password',
                                help='password.  If this argument is not passed it will be requested.')

        self._args = parser.parse_args()
        self._args.funct(self._args)

    def argparser_handler(self):
        if self._args.command == 'login':
            self.login()

    def login(self):
        if not self._username:
            self._username = input("User:")
        if not self._password:
            self._password = getpass.getpass()
        """ Get Cloud Services configuration """
        # create management client
        cs_client = ManagementClient(
            user=self._username, password=self._password)

        # create subscription client
        subscription_client = SubscriptionClient(cs_client)
        print(subscription_client)

        # get subscription detail
        self._subscription_id = subscription_client
        return self._subscription_id

def main():
    pass


if __name__ == "__main__":
    request = F5aaSSession()
    response = request.login()
    print(type(response))
    print(response)
    main()