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
#       CROSS_ACCOUNT_ROLE: target account's IAM Role name with cross account permissions
#       DAY_THRESHOLD: sets the TTL for DynamoDB entries; future logic implementation
#       DDB_BLOCK_LIST: table name for tracking IP addresses to block
#       DDB_NACL: table name for tracking NACL rule numbers
#       IP_WHITELIST: (future use) allows for explicit exemption of IP addresses
#       NACL_RULE_NUM: the initial rule number for rules associated with GaurdDuty Responder
# Permissions (currently lazy and needs to be dialed in):
#       sts:* for assuming roles
#       ec2:* for EC2 instance and NACL reading, eventually NACL writing
#       dynamodb:* for reading and writing items in DynamoDB table
#       logs:PutLogEvents restricted to specific log-group
#       logs:CreateLogStream restricted to specific log-group
#       logs:CreateLogGroup unrestricted
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
    log.info('Account Id: %s', accountId)

    description = finding['detail']['description']
    log.info('Description: %s', description)

    finding_type = finding['detail']['type']
    log.debug('Type: %s', finding_type)

    resource = finding['detail']['resource']
    log.debug('Resource: %s', resource)

    service = finding['detail']['service']
    log.debug('Service: %s', service)

    if (finding_type == 'Recon:EC2/PortProbeUnprotectedPort' or
        finding_type == 'UnauthorizedAccess:EC2/SSHBruteForce' or
        finding_type == 'UnauthorizedAccess:EC2/RDPBruteForce'):

        process_remote_access(finding,accountId,finding_type,client_ddb)
    else:
        log.info('There is no action to take for this finding type.')


def process_remote_access(finding,accountId,finding_type,client_ddb):
        instanceId = finding['detail']['resource']['instanceDetails']['instanceId']
        vpcId = finding['detail']['resource']['instanceDetails']['networkInterfaces'][0]['vpcId']
        subnetId = finding['detail']['resource']['instanceDetails']['networkInterfaces'][0]['subnetId']

        # cross account EC2 session
        role_arn = 'arn:aws:iam::' + accountId + ':role/' + os.environ['CROSS_ACCOUNT_ROLE']
        cross_account_session = aws_session(role_arn, 'guardduty_responder')
        #new
        resource_ec2 = cross_account_session.resource('ec2')
        client_ec2 = cross_account_session.client('ec2')
        naclId = get_nacl(client_ec2, subnetId)

        log.info('Must update NACL %s for instance %s in VPC %s due to %s', naclId, instanceId, vpcId, finding_type)

        if finding_type == 'Recon:EC2/PortProbeUnprotectedPort':

            for x in finding['detail']['service']['action']['portProbeAction']['portProbeDetails']:
                remoteIp = x['remoteIpDetails']['ipAddressV4']
                remoteCountry = x['remoteIpDetails']['country']['countryName']
                log.info('Must block the following remote ip %s originating from %s', remoteIp, remoteCountry)
                ddb_blocklist_update(client_ddb, instanceId, accountId, vpcId, subnetId, naclId, remoteIp, remoteCountry, client_ec2, resource_ec2)

        if (finding_type == 'UnauthorizedAccess:EC2/SSHBruteForce' or
            finding_type == 'UnauthorizedAccess:EC2/RDPBruteForce'):

            remoteIp = finding['detail']['service']['action']['networkConnectionAction']['remoteIpDetails']['ipAddressV4']
            remoteCountry = finding['detail']['service']['action']['networkConnectionAction']['remoteIpDetails']['country']['countryName']
            log.info('Must block the following remote ip %s originating from %s', remoteIp, remoteCountry)
            ddb_blocklist_update(client_ddb, instanceId, accountId, vpcId, subnetId, naclId, remoteIp, remoteCountry, client_ec2, resource_ec2)

        log.info('We can evaluate if count %s is above a configurable threshold', finding['detail']['service']['count'])

def ddb_blocklist_update(client_ddb, instanceId, accountId, vpcId, subnetId, naclId, remoteIp, remoteCountry, client_ec2, resource_ec2):

    # Establish dynamodb resource
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    ddb_block_list = dynamodb.Table(os.environ['DDB_BLOCK_LIST'])
    ddb_nacl_rule = dynamodb.Table(os.environ['DDB_NACL'])

    # TTL Stuff
    day_threshold = int(os.environ['DAY_THRESHOLD'])
    new_ttl = int(time.mktime((datetime.datetime.now() + datetime.timedelta(days=day_threshold)).timetuple()))

    ddb_block_list_key = {'instanceId': instanceId, 'remoteIp': remoteIp}
    response = ddb_block_list.get_item(Key=ddb_block_list_key)

    if response and 'Item' in response:
        # Instance and remoteIp pair already exist
        log.info('Updating TTL for already logged instance %s and source %s', instanceId, remoteIp)
        ddb_block_list.update_item(Key=ddb_block_list_key,
                                 UpdateExpression='SET #ttl = :ttl',
                                 ExpressionAttributeNames={'#ttl': 'TTL'},
                                 ExpressionAttributeValues={':ttl': new_ttl})

    else:
        # Instance and remoteIp pair are new
        if remoteIp not in os.environ['IP_WHITELIST']:
            log.info('Newly seen block: %s - %s in %s', instanceId, remoteIp, accountId)
            ddb_block_list.put_item(Item={'instanceId': instanceId,
                                        'accountId': accountId,
                                        'vpcId': vpcId,
                                        'subnetId': subnetId,
                                        'naclId': naclId,
                                        'remoteIp': remoteIp,
                                        'remoteCountry': remoteCountry,
                                        'TTL': new_ttl})

            # Check DDB for NACL rule number
            ddb_nacl_rule_key = {'naclId': naclId}
            response = ddb_nacl_rule.get_item(Key=ddb_nacl_rule_key)
            if response and 'Item' in response:
                # NACL entry exists in DynamoDB
                ruleNum = response['Item']['ruleNum']
                log.info('NACL found with rule number %s',ruleNum)
                # Increment the rule number
                ruleNum = int(ruleNum) +1
                ddb_nacl_rule.update_item(
                    Key=ddb_nacl_rule_key,
                    AttributeUpdates = {
                        'ruleNum': {
                                'Value': ruleNum,
                                'Action': 'PUT'
                            }
                    }
                )
                # Write new rule to NACL
                nacl_create_entry(naclId,ruleNum,remoteIp,client_ec2,resource_ec2)
            else:
                # NACL entry does not exist in DynamoDB; create with default rule number
                ruleNum = int(os.environ['NACL_RULE_NUM'])
                log.info('Registering new NACL %s with rule number %s',naclId,ruleNum)
                ddb_nacl_rule.put_item(Item={'naclId': naclId,
                                            'ruleNum': ruleNum})
                # Write new rule to NACL
                nacl_create_entry(naclId,ruleNum,remoteIp,client_ec2,resource_ec2)
        else:
            log.info('Remote %s is included in the whitelist and will not be blocked', remoteIp)


# NACL create entry
def nacl_create_entry(naclId,ruleNum,remoteIp,client_ec2,resource_ec2):

    #ec2 = boto3.resource('ec2')
    network_acl = resource_ec2.NetworkAcl(naclId)
    CidrBlock = remoteIp + "/32"

    response = network_acl.create_entry(
        CidrBlock=CidrBlock,
        DryRun = False,
        Egress = False,
        Protocol = "-1",
        RuleAction = 'deny',
        RuleNumber = ruleNum
    )
    log.info(response)


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
        log.debug('nacl: %s', NetworkAclId)
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
