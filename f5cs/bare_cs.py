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
from f5sdk.logger import Logger
# from netaddr import *


LOGGER = Logger(__name__).get_logger()


def parse_args():
    parser = argparse.ArgumentParser(description="command line client")
    subparsers = parser.add_subparsers(dest='command', metavar='command')
    subparsers.required = True
    parser.set_defaults(funct=argparser_handler)

    # Login
    sub_parser = subparsers.add_parser("login", help="Login with email and password")
    sub_parser.add_argument('-u', dest='user', help='user.  If this argument is not passed it will be requested.')
    sub_parser.add_argument('-p', dest='password',
                                help='password.  If this argument is not passed it will be requested.')

    args = parser.parse_args()
    args.funct(args)


def argparser_handler(args):
    if args.command == 'login':
        login(args.user, args.password)


def login(user, password, cs_token=None):
    if not user:
        user = input("User:")
    if not password:
        password = getpass.getpass()

    cs_client = ManagementClient(
        user=user, password=password)

    token = {'Authorization': 'Bearer {0}'.format(cs_client.access_token)}

    user = cs_client.make_request(uri='/v1/svc-account/user')
    primaryAccount = cs_client.make_request(uri='/v1/svc-account/accounts/{0}'.format(user['primary_account_id']))
    svcSubs = cs_client.make_request(uri='/v1/svc-subscription/subscriptions?account_id={0}'.format(primaryAccount['id']),
                                     headers=token)

    for subscription in primaryAccount['catalog_items']:
        if subscription['service_type'] == 'waf':
            print(json.dumps(subscription, indent=2))

    subscription_client = SubscriptionClient(cs_client)
    return subscription_client

if __name__ == "__main__":
    LOGGER.info(parse_args())