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
import os
import json
import argparse
import sys
from f5sdk.cloud_services import ManagementClient
from f5sdk.cloud_services.subscriptions import SubscriptionClient
from f5sdk.logger import Logger
from netaddr import *

LOGGER = Logger(__name__).get_logger()

class Interaction(object):
    def __init__(self):
        parser = argparse.ArgumentParser(
            description='F5aaS CloudServices',
            usage='''cloud_services.py <command> [<args>]

    There is a few ways to use this script:
        create      To create a Tiered AWS Environment
        delete      To delete the VPC and all associated resources/elements (TO BE DONE - not functioning, yet)
        ''')
        parser.add_argument('command', help='Parameters to pass for Environment Creation')
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print('Unrecognised command')
            parser.print_help()
            exit(1)
        getattr(self, args.command)()

    def create(self):
        parser = argparse.ArgumentParser(
            description='To create the AWS Tiered network Environment'
        )
        parser.add_argument('--name', type=str, required=False,
                            help='the customer code/reference to be used for creation.')
        args = parser.parse_args(sys.argv[2:])
        return args

class F5aaSSession(object):
    def __init__(self, username, region, role_session_name, mfa_serial, mfa_TOTP):
        self.arn = arn
        self.region = region
        self.role_session_name = role_session_name
        self.mfa_serial = mfa_serial
        self.mfa_TOTP = mfa_TOTP
        self._token = None
        self._aws_access_key_id = None
        self._aws_secret_access_key = None
        self._aws_session_token = None

    def get_cs_config():
        """ Get Cloud Services configuration """
        # create management client
        cs_client = ManagementClient(
            user=os.environ['F5_SDK_USERNAME'], password=os.environ['F5_SDK_PWD'])

        # create subscription client
        subscription_client = SubscriptionClient(cs_client)

        # get subscription details
        return subscription_client.show(name=os.environ['F5_SDK_CS_SUBSCRIPTION_ID'])

    def role_arn_to_session(self):
        client = boto3.client('sts')
        response = client.assume_role(
            RoleArn=self.arn,
            RoleSessionName=self.role_session_name,
            DurationSeconds=900,
            SerialNumber=self.mfa_serial,
            TokenCode=self.mfa_TOTP
        )
        self._aws_access_key_id = response['Credentials']['AccessKeyId'],
        self._aws_secret_access_key = response['Credentials']['SecretAccessKey'],
        self._aws_session_token = response['Credentials']['SessionToken'],
        self._token = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'],
            # TODO is to validate the requirement for profile (~/.aws/config or creds) sourcing
            # profile_name=self.role_session_profile,
            region_name=self.region
        )
        return self._token