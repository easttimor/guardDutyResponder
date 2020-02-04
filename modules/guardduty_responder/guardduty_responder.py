###############################################################################
# Name:
#       GuardDuty Responder
# Input:
#       CloudWatch Event, initiated by GuardDuty finding
# CloudWatch Event Rule:
#
# Description:
#
# Environment Variables:
#       LOG_LEVEL (optional): sets the level for function logging
#           valid input: critical, error, warning, info (default), debug
# Permissions:
#       sts for cross account role assumption
#       ec2 for describing and updating Network ACL
#       dynamodb for reading and writing dedicated table
###############################################################################

from botocore.exceptions import ClientError
import boto3
import collections
import datetime
import json
import logging
import os
import sys
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)
armed = "false"

###############################################################################
# LOGGING CONFIG
###############################################################################
DEFAULT_LOG_LEVEL = logging.INFO
LOG_LEVELS = collections.defaultdict(
    lambda: DEFAULT_LOG_LEVEL,
    {
        'critical': logging.CRITICAL,
        'error': logging.ERROR,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG
    }
)

# Lambda initializes a root logger that needs to be removed in order to set a
# different logging config
root = logging.getLogger()
if root.handlers:
    for handler in root.handlers:
        root.removeHandler(handler)

logging.basicConfig(
    format='%(asctime)s.%(msecs)03dZ [%(name)s][%(levelname)-5s]: %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
    level=LOG_LEVELS[os.environ.get('LOG_LEVEL', '').lower()])

log = logging.getLogger(__name__)


###############################################################################
# HANDLER
###############################################################################
def lambda_handler(event, context):
    # Log the raw JSON for the inbound event
    log.info('Raw event: %s', event)
    log.info('Event details: %s', event['detail'])

    # set up for DynamoDB
    client_ddb = boto3.client('dynamodb')

    # event parsing
    finding = event

    detail = finding['detail']
    log.info(detail)

    # get finding account and build ARN
    accountId = finding['detail']['accountId']
    log.info(accountId)

    description = finding['detail']['description']
    log.info('Description: %s', description)

    finding_type = finding['detail']['type']
    log.debug('Type: %s', finding_type)

    resource = finding['detail']['resource']
    log.debug('Resource: %s', resource)

    service = finding['detail']['service']
    log.debug('Service: %s', service)

    if finding_type == 'Recon:EC2/PortProbeUnprotectedPort':
        instanceId = finding['detail']['resource']['instanceDetails']['instanceId']
        vpcId = finding['detail']['resource']['instanceDetails']['networkInterfaces'][0]['vpcId']
        subnetId = finding['detail']['resource']['instanceDetails']['networkInterfaces'][0]['subnetId']

        # cross account EC2 session
        role_arn = 'arn:aws:iam::' + accountId + ':role/' + os.environ['CROSS_ACCOUNT_ROLE']
        cross_account_session = aws_session(role_arn, 'guardduty_responder')
        client_ec2 = cross_account_session.client('ec2')
        nacl = get_nacl(client_ec2, subnetId)

        log.info('Must update NACL %s for instance %s in VPC %s due to %s', nacl, instanceId, vpcId, finding_type)

        for x in finding['detail']['service']['action']['portProbeAction']['portProbeDetails']:
            remoteIp = x['remoteIpDetails']['ipAddressV4']
            remoteCountry = x['remoteIpDetails']['country']['countryName']
            log.info('Must block the following remote ip %s originating from %s', remoteIp, remoteCountry)
            dynamodb_update(client_ddb, instanceId, accountId, vpcId, subnetId, nacl, remoteIp, remoteCountry)
        log.info('We can evaluate if count %s is above a configurable threshold', finding['detail']['service']['count'])


def dynamodb_update(client_ddb, instanceId, accountId, vpcId, subnetId, remoteIp, remoteCountry):

    # Establish dynamodb resource
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    dynamo_table = dynamodb.Table(os.environ['DYNAMO_TABLE'])

    # TTL Stuff
    day_threshold = int(os.environ['DAY_THRESHOLD'])
    new_ttl = int(time.mktime((datetime.datetime.now() + datetime.timedelta(days=day_threshold)).timetuple()))

    ddb_key = {'instanceId': instanceId, 'remoteIp': remoteIp}
    response = dynamo_table.get_item(Key=ddb_key)

    if response and 'Item' in response:
        # Instance and remoteIp pair already exist
        log.info('Already logged instance %s and source %s', instanceId, remoteIp)
        dynamo_table.update_item(Key=ddb_key,
                                 UpdateExpression='SET #ttl = :ttl',
                                 ExpressionAttributeNames={'#ttl': 'TTL'},
                                 ExpressionAttributeValues={':ttl': new_ttl})
    else:
        # Instance and remoteIp pair are new
        if remoteIp not in os.environ['IP_WHITELIST']:
            log.info('Newly seen block: %s - %s in %s', instanceId, remoteIp, accountId)
            dynamo_table.put_item(Item={'instanceId': instanceId,
                                        'accountId': accountId,
                                        'vpdId': vpcId,
                                        'subnetId': subnetId,
                                        'remoteIp': remoteIp,
                                        'remoteCountry': remoteCountry,
                                        'TTL': new_ttl})
        else:
            log.info('Remote %s is included in the whitelist and will not be blocked', remoteIp)


# Use the EC2 instance's subnet to determine the id of the associated Network ACL
def get_nacl(client_ec2, subnetId):

    response = client_ec2.describe_network_acls(
        Filters=[
            {
                'Name': 'association.subnet-id',
                'Values': [
                        subnetId
                    ]
            }
        ]
    )

    # index 0 should be fine as only one list item is expected
    if response and 'NetworkAclId' in response['NetworkAcls'][0]:
        NetworkAclId = response['NetworkAcls'][0]['NetworkAclId']
        log.info('nacl: %s', NetworkAclId)
        return NetworkAclId
    else:
        log.info('Could not determine NACL to update')
        return null


# Establish cross account session
def aws_session(role_arn, session_name):

    client = boto3.client('sts')
    response = client.assume_role(
            RoleArn=role_arn, RoleSessionName=session_name
        )
    return boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
