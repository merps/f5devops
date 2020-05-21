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
import os, sys, json, requests
import argparse, getpass
from f5sdk.cs import ManagementClient
from f5sdk.cs.accounts import AccountClient
from f5sdk.cs.subscriptions import SubscriptionClient
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

    mgmt_client = ManagementClient(
        user=user, password=password)

    token = {'Authorization': 'Bearer {0}'.format(cs_client.access_token)}

    user = cs_client.make_request(uri='/v1/svc-account/user')
    something = json.dumps(user, indent=2)
    print(something)

    # primaryAccount = cs_client.make_request(uri='/v1/svc-account/accounts/{0}'.format(user['primary_account_id']))
    account_id = account_client.show_user()['primary_account_id']

    svcSubs = cs_client.make_request(uri='/v1/svc-subscription/subscriptions?account_id={0}'.format(primaryAccount['id']),
                                    headers=token)
    print("====================List using new cs modules====================")
    subscription_id = subscription_client.list(
	query_paramters={
	    'account_id': account_id
	}
	)['subscriptions'][0]['subscription_id']

    print(subscription_id)

    print("====================List using new cs dns========================")
    print(json.dumps(subscription_id, indent=4)

    for sub_id in svcSubs['subscriptions']:
        print(json.dumps(sub_id, indent=2))
        request_json = '{"waf_service_eventsServiceEventsQueryRequest"}'
        test = cs_client.make_request(uri='/v1/svc-subscription/subscriptions/{0}/test'.format(sub_id['subscription_id']), method='GET', headers=token, 
                                    body=request_json)
        print(json.dumps(test, indent=2))

    for subscription in primaryAccount['catalog_items']:
        if subscription['service_type'] == 'waf':
            print(json.dumps(subscription, indent=2))

    subscription_client = SubscriptionClient(cs_client)
    return subscription_client

if __name__ == "__main__":
    LOGGER.info(parse_args()) 
