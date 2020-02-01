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
def guardduty_responder(event, context):
    log.info(event)