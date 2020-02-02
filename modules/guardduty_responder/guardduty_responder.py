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
#       
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

    # set up for DynamoDB
    client_ddb = boto3.client('dynamodb')

    # event parsing
    finding = json.loads(event['Message'])
    
    detail = finding['detail']
    log.info(detail)
    
    accountId = finding['detail']['accountId']
    log.info(accountId)

    description = finding['detail']['description']
    log.info('Description: %s',description)
    
    finding_type = finding['detail']['type']
    log.debug('Type: %s', finding_type)
    
    resource = finding['detail']['resource']
    log.debug('Resource: %s', resource)

    service = finding['detail']['service']
    log.debug('Service: %s', service)
    
    if finding_type == 'Recon:EC2/PortProbeUnprotectedPort':
        instanceId = finding['detail']['resource']['instanceDetails']['instanceId']
        vpcId = finding['detail']['resource']['instanceDetails']['networkInterfaces'][0]['vpcId']
        log.info('Must update NACL for instance %s in VPC %s due to %s', instanceId, vpcId, finding_type)
        #log.info(finding['detail']['service']['action']['portProbeAction']['portProbeDetails'][0]['remoteIpDetails'])
        for x in finding['detail']['service']['action']['portProbeAction']['portProbeDetails']:
            remoteIp = x['remoteIpDetails']['ipAddressV4']
            remoteCountry = x['remoteIpDetails']['country']['countryName']
            log.info('Must block the following remote ip %s originating from %s', remoteIp, remoteCountry)
            dynamodb_update(client_ddb, instanceId, accountId, vpcId, remoteIp, remoteCountry)
        log.info('We can evaluate if count %s is above a configurable threshold', finding['detail']['service']['count'])
    
def dynamodb_update(client_ddb, instanceId, accountId, vpcId, remoteIp, remoteCountry):

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
                                        'remoteIp': remoteIp,
                                        'vpdId': vpcId,
                                        'remoteCountry': remoteCountry,
                                        'TTL': new_ttl})
        else:
            log.info('Remote %s is included in the whitelist and will not be blocked', remoteIp)
