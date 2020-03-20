"""
Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.


This script orchestrates the enablement and centralization of SecurityHub
across an enterprise of AWS accounts.
It takes in a list of AWS Account Numbers, iterates through each account and
region to enable SecurityHub.
It creates each account as a Member in the SecurityHub Master account.
It invites and accepts the invite for each Member account.
The Security Hub automation is based on the scripts published at
https://github.com/awslabs/aws-securityhub-multiaccount-scripts
"""

import boto3
import json
import requests
import os
import logging
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
if 'log_level' in os.environ:
    LOGGER.setLevel(os.environ['log_level'])
    LOGGER.info("Log level set to %s" % LOGGER.getEffectiveLevel())
else:
    LOGGER.setLevel(logging.ERROR)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

session = boto3.Session()


def send(
  event, context, responseStatus, responseData,
  physicalResourceId=None, noEcho=False):
    responseUrl = event['ResponseURL']

    print(responseUrl)
    ls = context.log_stream_name
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + ls
    responseBody['PhysicalResourceId'] = physicalResourceId or ls
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = noEcho
    responseBody['Data'] = responseData

    json_responseBody = json.dumps(responseBody)

    print("Response body:\n" + json_responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        print("Status code: " + response.reason)
    except Exception as e:
        print("send(..) failed executing requests.put(..): " + str(e))


def get_enabled_regions(session, regions):
    """
    With the introduction of regions that can be disabled,
    it is necessary to test to see if a region can be used
    and not just assume we can enable it.
    """
    enabled_regions = []
    for region in regions:
        sts_client = session.client('sts', region_name=region)
        try:
            sts_client.get_caller_identity()
            enabled_regions.append(region)
        except ClientError as e:
            if e.response['Error']['Code'] == "InvalidClientTokenId":
                LOGGER.info("%s region is disabled." % (region))
            else:
                # LOGGER.debug("Error %s %s" % (e.response['Error'],region))
                err = e.response['Error']
                LOGGER.error(
                    "Error %s occurred testing region %s" % (err, region))
    return enabled_regions


def get_account_list():
    """
    Gets a list of Active AWS Accounts in the Organization.
    This is called if the function is not executed by an SNS trigger and
    used to periodically ensure all accounts are correctly configured, and
    prevent gaps in security from activities like new regions being added and
    SecurityHub being disabled while respecting OU filters.
    """
    aws_accounts_dict = dict()
    # Get list of accounts in org
    orgclient = session.client('organizations', region_name='us-east-1')
    accounts = orgclient.list_accounts()
    ctonly = False
    if os.environ['ou_filter'] == 'ControlTower':
        ctonly = True
    while 'NextToken' in accounts:
        moreaccounts = orgclient.list_accounts(NextToken=accounts['NextToken'])
        for acct in accounts['Accounts']:
            moreaccounts['Accounts'].append(acct)
        accounts = moreaccounts
    LOGGER.debug(accounts)
    LOGGER.info('Total accounts: {}'.format(len(accounts['Accounts'])))
    for account in accounts['Accounts']:
        ctaccount = False
        if ctonly:
            # find account OU to test it for CT policies
            parent = orgclient.list_parents(
                ChildId=account['Id']
            )['Parents'][0]['Id']
            # enumerate policies for the account so we can look for Control
            # Tower SCPs
            policies = orgclient.list_policies_for_target(
                TargetId=parent,
                Filter="SERVICE_CONTROL_POLICY"
            )
            for policy in policies['Policies']:
                if policy['Name'][:15] == 'aws-guardrails-':
                    # Found a CT account so setting flag
                    ctaccount = True
        # Store accounts matching the oufilter that are active accounts in a
        # dict
        if ctaccount == ctonly and account['Status'] == 'ACTIVE':
            accountid = account['Id']
            email = account['Email']
            aws_accounts_dict.update({accountid: email})
    LOGGER.info('Active accounts count: %s, Active accounts: %s' % (
        len(aws_accounts_dict.keys()), json.dumps(aws_accounts_dict)))
    return aws_accounts_dict


def assume_role(aws_account_number, role_name):
    """
    Assumes the provided role in each account and returns a session object
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call
    :return: Session object for the specified AWS Account and Region
    """
    sts_client = boto3.client('sts')
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
    current_account = sts_client.get_caller_identity()['Arn'].split(":")[4]
    if aws_account_number == current_account:
        LOGGER.info("Using existing session for %s." % (aws_account_number))
        return session
    else:
        response = sts_client.assume_role(
            RoleArn='arn:%s:iam::%s:role/%s' % (
                partition, aws_account_number, role_name),
            RoleSessionName='EnableSecurityHub'
        )
        sts_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
        LOGGER.info("Assumed session for %s." % (aws_account_number))
        return sts_session


def get_master_members(master_session, aws_region):
    """
    Returns a list of current members of the SecurityHub master account
    :param aws_region: AWS Region of the SecurityHub master account
    :return: dict of AwsAccountId:MemberStatus
    """
    member_dict = dict()
    sh_client = master_session.client('securityhub', region_name=aws_region)
    # Need to paginate and iterate over results
    paginator = sh_client.get_paginator('list_members')
    operation_parameters = {
        'OnlyAssociated': False
    }
    page_iterator = paginator.paginate(**operation_parameters)
    for page in page_iterator:
        if page['Members']:
            for member in page['Members']:
                member_dict.update(
                    {
                        member['AccountId']: member['MemberStatus']
                    }
                )
    return member_dict


def enable_cis_benchmark(sh_client, partition):
    CIS_BENCHMARK_ARN = (
        'arn:%s:securityhub:::ruleset/'
        'cis-aws-foundations-benchmark/v/1.2.0' % (partition))
    enabled_standards = sh_client.get_enabled_standards()
    if len(enabled_standards['StandardsSubscriptions']) > 0:
        LOGGER.info(
            "Standards are already enabled: %s" % (
                enabled_standards['StandardsSubscriptions']))
        return None
    sh_client.batch_enable_standards(
        StandardsSubscriptionRequests=[
            {
                'StandardsArn': CIS_BENCHMARK_ARN
            }
        ]
    )


def get_ct_regions(session):
    # This is a hack to find the control tower supported regions, as there
    # is no API for it right now it enumerates the
    # AWSControlTowerBP-BASELINE-CLOUDWATCH CloudFormation StackSet and finds
    # what regions it has deployed stacks too.
    # It doesn't have to evaluate enabled_regions as only enabled regions
    # will/can have stacks deployed
    cf = session.client('cloudformation')
    stacks = cf.list_stack_instances(
        StackSetName='AWSControlTowerBP-BASELINE-CLOUDWATCH')
    region_set = set()
    for stack in stacks['Summaries']:
        region_set.add(stack['Region'])
    return list(region_set)


def disable_master(master_session, role, securityhub_regions, partition):
    for region in securityhub_regions:
        sh_master_client = master_session.client(
            'securityhub', region_name=region)
        master_members = get_master_members(master_session, region)
        member_accounts = []
        for member in master_members:
            member_accounts.append(member)
            member_session = assume_role(member, role)
            member_client = member_session.client(
                'securityhub', region_name=region)
            member_client.disable_security_hub()
            LOGGER.info(
                'SecurityHub disabled in member Account %s in %s' % (
                    member, region))
        sh_master_client.disassociate_members(AccountIds=member_accounts)
        sh_master_client.delete_members(AccountIds=member_accounts)
        try:
            sh_master_client.disable_security_hub()
            LOGGER.info(
                'SecurityHub disabled in Master Account in %s' % (region))
        except Exception:
            LOGGER.info(
                'SecurityHub already disabled in Master Account in %s' % (
                    region))
    return


def enable_master(master_session, securityhub_regions, partition):
    for region in securityhub_regions:
        sh_master_client = master_session.client(
            'securityhub', region_name=region)

        # Making sure SecurityHub is enabled in the Master Account
        try:
            sh_master_client.get_findings()
        except Exception:
            LOGGER.info("SecurityHub not currently enabled on Master account "
                        "in %s. Enabling it." % (region))
            sh_master_client.enable_security_hub()
        else:
            # Security Hub already enabled
            LOGGER.info('SecurityHub already enabled in Master Account in '
                        '%s' % (region))
        LOGGER.info(
            'Enabling CIS Benchmark in Master Account in %s' % (region))
        enable_cis_benchmark(sh_master_client, partition)
    return


def lambda_handler(event, context):
    LOGGER.info('REQUEST RECEIVED: %s' % (json.dumps(event, default=str)))
    partition = context.invoked_function_arn.split(":")[1]
    master_account_id = os.environ['sh_master_account']
    master_session = assume_role(master_account_id, os.environ['assume_role'])
    if os.environ['region_filter'] == 'SecurityHub':
        securityhub_regions = get_enabled_regions(
            session, session.get_available_regions('securityhub'))
    else:
        securityhub_regions = get_ct_regions(session)
    # Check for custom resource call
    if 'RequestType' in event and (
            event['RequestType'] == "Delete" or
            event['RequestType'] == "Create" or
            event['RequestType'] == "Update"):
        action = event['RequestType']
        if action == "Create":
            enable_master(master_session, securityhub_regions, partition)
        if action == "Delete":
            disable_master(
                master_session,
                os.environ['assume_role'],
                securityhub_regions,
                partition)
        responseData = {}
        LOGGER.info('Sending custom resource response')
        send(event, context, "SUCCESS", responseData)
        if action == "Delete":
            # Exit on delete so it doesn't re-enable existing accounts
            raise SystemExit()
    else:
        action = 'Create'
    LOGGER.info(
        "Enabling SecurityHub in regions %s" % (securityhub_regions))
    aws_account_dict = dict()
    # Checks if function was called by SNS
    if 'Records' in event:
        message = event['Records'][0]['Sns']['Message']
        jsonmessage = json.loads(message)
        LOGGER.info('SNS message: %s' % (
            json.dumps(jsonmessage, default=str)))
        accountid = jsonmessage['AccountId']
        email = jsonmessage['Email']
        aws_account_dict.update({accountid: email})
        action = jsonmessage['Action']
    # Checks if function triggered by Control Tower Lifecycle Event,
    # testing in multiple steps to ensure invalid values
    # short-circuit it instead of failing
    elif ('detail' in event) and (
        'eventName' in event['detail']) and (
            event['detail']['eventName'] == 'CreateManagedAccount'):
        servicedetail = event['detail']['serviceEventDetails']
        status = servicedetail['createManagedAccountStatus']
        LOGGER.info(
            'Control Tower Event: CreateManagedAccount %s' % (status)
            )
        accountid = status['account']['accountId']
        email = session.client('organizations').describe_account(
            AccountId=accountid)['Account']['Email']
        aws_account_dict.update({accountid: email})
    else:
        # Not called by SNS or CloudFormation event, iterates through list of
        # accounts and recursively calls the function itself via SNS. SNS is
        # used to fan out the requests to avoid function timeout if too many
        # accounts
        aws_account_dict = get_account_list()
        snsclient = session.client('sns', region_name=os.environ['AWS_REGION'])
        for accountid, email in aws_account_dict.items():
            sns_message = {
                'AccountId': accountid,
                'Email': email,
                'Action': action
            }
            LOGGER.info("Publishing to configure account %s" % (accountid))
            snsclient.publish(
                TopicArn=os.environ['topic'], Message=json.dumps(sns_message))
        return
    # Ensure the security master is still enabled
    enable_master(master_session, securityhub_regions, partition)

    LOGGER.info('Processing: %s' % (json.dumps(aws_account_dict)))
    for account in aws_account_dict.keys():
        email_address = aws_account_dict[account]
        if account == master_account_id:
            LOGGER.info("%s cannot become a member of itself" % (account))
            continue
        failed_invitations = []
        LOGGER.debug(
            "Working on SecurityHub on account %s in regions %s" % (
                securityhub_regions, account))
        member_session = assume_role(account, os.environ['assume_role'])
        for aws_region in securityhub_regions:
            sh_member_client = member_session.client(
                'securityhub', region_name=aws_region)
            sh_master_client = master_session.client(
                'securityhub', region_name=aws_region)
            master_members = get_master_members(master_session, aws_region)
            LOGGER.info('Beginning %s in %s' % (
                        account, aws_region))
            if account in master_members:
                if master_members[account] == 'Associated':
                    LOGGER.info(
                        "%s is already associated with %s in %s" % (
                            account, master_account_id, aws_region))
                    if action == 'Delete':
                        try:
                            sh_master_client.disassociate_members(
                                AccountIds=[account])
                        except Exception:
                            continue
                        try:
                            sh_master_client.delete_members(
                                AccountIds=[account])
                        except Exception:
                            continue
                else:
                    LOGGER.warning(
                        "%s exists, but not associated to %s in %s" % (
                            account, master_account_id, aws_region))
                    LOGGER.info(
                        "Disassociating %s from %s in %s" % (
                            account, master_account_id, aws_region))
                    try:
                        sh_master_client.disassociate_members(
                            AccountIds=[account])
                    except Exception:
                        continue
                    try:
                        sh_master_client.delete_members(
                            AccountIds=[account])
                    except Exception:
                        continue

            try:
                sh_member_client.get_findings()
            except Exception as e:
                LOGGER.debug(str(e))
                LOGGER.info(
                    "SecurityHub not currently enabled on %s in %s" % (
                        account, aws_region))
                if action != 'Delete':
                    LOGGER.info("Enabling SecurityHub on %s in %s" % (
                        account, aws_region))
                    sh_member_client.enable_security_hub()
            else:
                # Security Hub already enabled
                if action != 'Delete':
                    LOGGER.info(
                        'SecurityHub already enabled in %s in %s' % (
                            account, aws_region))
                else:
                    try:
                        sh_member_client.disable_security_hub()
                    except Exception:
                        continue
            if action != 'Delete':
                LOGGER.info('Enabling CIS Benchmark in %s in %s' % (
                    account, aws_region))
                enable_cis_benchmark(sh_member_client, partition)

                LOGGER.info("Creating member for %s and %s in %s" % (
                    account, email_address, aws_region))
                member_response = sh_master_client.create_members(
                    AccountDetails=[{
                        'AccountId': account,
                        'Email': email_address
                    }])

                if len(member_response['UnprocessedAccounts']) > 0:
                    LOGGER.warning("Could not create member %s in %s" % (
                        account, aws_region))
                    failed_invitations.append({
                        'AccountId': account, 'Region': aws_region
                    })
                    continue
                LOGGER.info("Inviting %s in %s" % (
                    account, aws_region))
                sh_master_client.invite_members(AccountIds=[account])

            # go through each invitation (hopefully only 1)
            # and pull the one matching the Security Master Account ID
            try:
                paginator = sh_member_client.get_paginator(
                    'list_invitations')
                invitation_iterator = paginator.paginate()
                for invitation in invitation_iterator:
                    master_invitation = next(
                        item for item in invitation['Invitations'] if
                        item["AccountId"] == master_account_id)

                LOGGER.info(
                    "Accepting invitation on %s from %s in %s" % (
                        account, master_account_id, aws_region))

                sh_member_client.accept_invitation(
                    MasterId=master_account_id,
                    InvitationId=master_invitation['InvitationId'])
            except Exception as e:
                LOGGER.warning(
                    "%s could not accept invitation from %s in %s" % (
                        account, master_account_id, aws_region))
                LOGGER.warning(e)
        if len(failed_invitations) > 0:
            LOGGER.warning("Error Processing following accounts: %s" % (
                json.dumps(failed_invitations, sort_keys=True, default=str)))
