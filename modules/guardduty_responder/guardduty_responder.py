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
    finding = json.loads(event['Message'])
    
    detail = finding['detail']
    log.info(detail)
    
    accountId = finding['detail']['accountId']
    log.info(accountId)

    description = finding['detail']['description']
    log.info('Description: %s',description)
    
    finding_type = finding['detail']['type']
    log.info('Type: %s', finding_type)
    
    resource = finding['detail']['resource']
    log.info('Resource: %s', resource)

    service = finding['detail']['service']
    log.info('Service: %s', service)
    
    if finding_type == 'Recon:EC2/PortProbeUnprotectedPort':
        instanceId = finding['detail']['resource']['instanceDetails']['instanceId']
        vpcId = finding['detail']['resource']['instanceDetails']['networkInterfaces'][0]['vpcId']
        log.info('Must update NACL for instance %s in VPC %s', instanceId, vpcId)
        #log.info(finding['detail']['service']['action']['portProbeAction']['portProbeDetails'][0]['remoteIpDetails'])
        remoteIp = finding['detail']['service']['action']['portProbeAction']['portProbeDetails'][0]['remoteIpDetails']['ipAddressV4']
        remoteCountry = finding['detail']['service']['action']['portProbeAction']['portProbeDetails'][0]['remoteIpDetails']['country']['countryName']
        log.info('Must block the following remote ip %s originating from %s', remoteIp, remoteCountry)
