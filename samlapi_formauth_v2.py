#!/usr/bin/env python3
import sys
# Let the script know where to find modules
# add entry to the from of the list of paths
# to give locally installed modules preference
sys.path = ['.'] + sys.path
sys.path = ['./modules'] + sys.path
import requests
import argparse
import getpass
import logging  as log
from bs4 import BeautifulSoup
import boto3
import xml.etree.ElementTree as ET
import base64
import os
import configparser
from botocore.config import Config

parser = argparse.ArgumentParser(prog='samlapi_formauth', description='Obtainand store AWS credentials using ADFS Saml assertion',formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('--version', action='version', version='%(prog)s 2.0')
parser.add_argument("-o", "--profile", dest="profile", default="saml", action="store", help="specify profile name where to store AWS credentials")
parser.add_argument("-r", "--region", dest="region", default="eu-west-1", action="store", help="specify region where to create sts session")
parser.add_argument("-t", "--output", dest="output", default="json", choices=['json','test','table','yaml','yaml-stream'], action="store", help="specify default output format to be stored in AWS Cli config")
parser.add_argument("-a", "--role-arn", dest="rolearn", default="", action="store", help="specify role arn to be automaticaly selected")
parser.add_argument("-c", "--aws-config-file", dest="awsconfigfile", default="/.aws/credentials", action="store", help="AWS cli credential file location")
parser.add_argument("-l", "--idp-entry-url", dest="idpentryurl", default="https://sts.contoso.com/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices", action="store", help="AWS cli credential file location")
parser.add_argument("-u", "--username", dest="username", default="", action="store", help="user name")
parser.add_argument("-p", "--password", dest="password", default="", action="store", help="password")
parser.add_argument("-s", "--session-duration", dest="sessionduration", default=28800, action="store", help="change session duration in seconds")
parser.add_argument("-x", "--proxy", dest="proxy", default="http://proxy.com:3128", action="store", help="setup proxy server to be used")
parser.add_argument("-n", "--no-ssl-verify", dest="nosslverification", default=False, action="store_true", help="disable ssl verification")
parser.add_argument("-f", "--force", dest="force", default=False, action="store_true", help="force SAML token renewal")
parser.add_argument("-e", "--set-env-vars", dest="setenvvars", default=False, action="store_true", help="store AWS credential to environmnet variables")
parser.add_argument("-d", "--store-as-default", dest="storeasdefault", default=False, action="store_true", help="store AWS credential also as DEFAULT profile")
parser.add_argument("-v", "--verbose", dest="verbose", default=False, action="store_true", help="enable verbose mode")
args = parser.parse_args()

print("Starting ADFS SAML process...")

def quit_message():
    print("Use -v, --verbose parameter for more infomration") if not args.verbose else None

if args.verbose:
    log.basicConfig(format="%(levelname)s: %(message)s", level=log.INFO)
    log.info("Verbose output enabled")
else:
    log.basicConfig(format="%(levelname)s: %(message)s")

log.info("Using following parameter values:")
log.info(">> profile: %s", args.profile)
log.info(">> region: %s", args.region)
log.info(">> output: %s", args.output)
log.info(">> role arn: %s", args.rolearn)
log.info(">> aws config file: %s", args.awsconfigfile)
log.info(">> idp entry url: %s", args.idpentryurl)
log.info(">> username: %s", args.username)
log.info(">> session duration: %s", args.sessionduration)
log.info(">> proxy: %s", args.proxy)
log.info(">> no ssl verification: %s", args.nosslverification)
log.info(">> force: %s", args.force)
log.info(">> set env vars: %s", args.setenvvars)
log.info(">> store as default: %s", args.storeasdefault)

##########################################################################
# Variables

username = args.username
password = args.password
# proxy details
proxy = {}; proxy['https'] = args.proxy

##########################################################################

# Test existing credentials
try:
    log.info('Validating credential from profile [{0}]'.format(args.profile))
    s3conn = boto3.Session(
        profile_name = args.profile,
        region_name = region
    )
    s3 = s3conn.resource('s3',config=Config(proxies=proxy))
    buckets = [bucket.name for bucket in s3.buckets.all()]
    log.info('Valid credential are still available. No need to refresh. Use --force to force resfresh')
except:
    log.info('Credentials expired, processing to refresh...')

if 'USERDOMAIN' in os.environ:
    currentuser  =  getpass.getuser() + '@' + os.environ['USERDOMAIN']
else:
    currentuser  =  getpass.getuser()

# Get the federated credentials from the user
if username in (None, '') or not username.strip():
    print("\nInput your corp domain credentials \n")
    username = input("Username [{0}]: ".format(currentuser))
    if username in (None, '') or not username.strip():
        username = currentuser.strip()

if password in (None, '') or not password.strip():
    password = getpass.getpass("Password for [{0}]:".format(username))
    print(' \n')

if username in (None, '') or not username.strip():
    log.error('empty username. it must be provided...')
    quit_message()
    quit(1)

log.info("Using username: [{0}]".format(username))

# Initiate session handler
session = requests.Session()

payload = {}
payload['username']=username
payload['password']=password
payload['authentication']='FormsAuthentication'

# Programmatically get the SAML assertion
# Opens the IdP url and follows all of the HTTP302 redirects, and
log.info("Calling ADFS endpoint [{0}]".format(args.idpentryurl))
response = session.post(args.idpentryurl, data=payload, verify=not args.nosslverification)

# Debug the parameter payload if needed
# Use with caution since this will print sensitive output to the screen
# print ">>>>>>>>>>>>>> Payload: ", payload

# Debug the response if needed
# print (response.text)

# Overwrite and delete the credential variables, just for safety
username = '##############################################'
password = '##############################################'
del username
del password

samlresponseencoded = ''
# Look for the SAMLResponse attribute of the input tag (determined by
# analyzing the debug print lines above)
soup = BeautifulSoup(response.text,'html.parser')
for inputtag in soup.find_all('input'):
    if(inputtag.get('name') == 'SAMLResponse'):
        samlresponseencoded = inputtag.get('value')

# Better error handling is required for production use.
if (samlresponseencoded == ''):
    log.error('No valid ADFS assertion received, please try again...')
    log.error('Suggestion: Check your username and password or supply alternative credentials.')
    quit_message()
    quit(1)

# Debug only
# print(base64.b64decode(assertion))

# # Parse the returned assertion and extract the authorized roles
awsroles = []
samlresponse = ET.fromstring(base64.b64decode(samlresponseencoded))
for saml2attribute in samlresponse.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/SessionDuration'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            samlsessionduration = int(saml2attributevalue.text)
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/RoleSessionName'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            samlrolesessionname = saml2attributevalue.text

log.info("Returned SAML assertion attributes:")
log.info(">> session role name: {0}".format(samlrolesessionname))
log.info(">> session duration: {0}".format(samlsessionduration))


if len(awsroles) == 0:
    log.error("No roles to assume has been returned, please try again...")
    log.error('Suggestion: Check your username and password or supply alternative credentials.')
    quit_message()
    quit(1)

# if rolearn parameter provided  try to find in saml response
selectedroleindex = -1
if not(args.rolearn in (None, '') or not args.rolearn.strip()):
    log.info("Looking for role [{0}] in SAML response...".format(args.rolearn))
    for i,j in enumerate(awsroles):
      selectedroleindex = i
      if args.rolearn in j:
        log.info("...role found and selected")
        break
    if (selectedroleindex == len(awsroles)-1) and (args.rolearn not in awsroles[selectedroleindex]):
        selectedroleindex = -1
        log.info("...not found")

if selectedroleindex == -1:
    if len(awsroles) > 1:
        i = 0
        print("Please choose the role you would like to assume:")
        for awsrole in awsroles:
            print ('[', i, ']: ', awsrole.split(',')[1])
            i += 1
        print ("Selection: ",  end=" ")
        selectedroleindexinput = input()
        # Basic sanity check of input
        if selectedroleindexinput.isdigit():
            if int(selectedroleindexinput) in range(0, len(awsroles)):
                selectedroleindex = int(selectedroleindexinput)
            else:
                log.error('Index out of range. Must be number between 0 nad {0}, please try again...'.format(len(awsroles)-1))
                quit_message()
                quit(1)
        else:
            log.error('Invalid index. Must be number between 0 nad {0}, please try again...'.format(len(awsroles)-1))
            quit_message()
            quit(1)
    else:
        log.warning("only single role returned which does not match one provided as parameter") if not(args.rolearn in (None, '') or not args.rolearn.strip()) else None
        selectedroleindex = 0
selectedrolearn = awsroles[selectedroleindex].split(',')[1]
selectedprincipalarn = awsroles[selectedroleindex].split(',')[0]

# Use the assertion to get an AWS STS token using Assume Role with SAML
downgrade = False
try:
    log.info('Assuming role [{0}]...'.format(selectedrolearn))
    token = boto3.client('sts',config=Config(proxies=proxy)).assume_role_with_saml(
        RoleArn=selectedrolearn,
        PrincipalArn=selectedprincipalarn,
        SAMLAssertion=samlresponseencoded,
        DurationSeconds=samlsessionduration
    )
    log.info('...done')
except:
    e = sys.exc_info()
    log.warning("Could not assume role [{0}]".format(selectedrolearn))
    for x in range(len(e)):
        log.warning(">>> {0}".format(e[x]))
    log.warning('Will try to downgrade session duration...')
    downgrade = True

# if previous call failed then try to call again with downgraded session duration
if downgrade:
    log.info('Downgrading session duration to 28800 seconds...')
    try:
        log.info('Assuming role [{0}]...'.format(selectedrolearn))
        token = boto3.client('sts',config=Config(proxies=proxy)).assume_role_with_saml(
            RoleArn=selectedrolearn,
            PrincipalArn=selectedprincipalarn,
            SAMLAssertion=samlresponseencoded,
            DurationSeconds=28800
        )
        log.info('...done')
    except:
        e = sys.exc_info()
        log.error("Could not assume role [{0}]".format(selectedrolearn))
        for x in range(len(e)):
            log.error(">>> {0}".format(e[x]))
        log.error('Suggestion: Check your username and password or supply alternative credentials.')
        quit_message()
        quit(1)

# Write the AWS STS token into the AWS credential file
home = os.path.expanduser("~")
filename = home + args.awsconfigfile

# Read in the existing config file
config = configparser.RawConfigParser()
config.read(filename)

# Put the credentials into saml profile
if not config.has_section(args.profile):
    config.add_section(args.profile)
config.set(args.profile, 'output', args.output)
config.set(args.profile, 'region', args.region)
config.set(args.profile, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
config.set(args.profile, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
config.set(args.profile, 'aws_session_token', token['Credentials']['SessionToken'])

# Put the credentials into default profile
if args.storeasdefault:
    if not config.has_section('default'):
        config.add_section('default')
    config.set('default', 'output', args.output)
    config.set('default', 'region', args.region)
    config.set('default', 'aws_access_key_id', token['Credentials']['AccessKeyId'])
    config.set('default', 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
    config.set('default', 'aws_session_token', token['Credentials']['SessionToken'])

# Write the updated config file
log.info('Saving credentials to config file [{0}]'.format(filename))
with open(filename, 'w+') as configfile:
    config.write(configfile)

if args.setenvvars:
    log.info('Storing AWS credentials in environment variables')
    os.environ['AWS_ACCESS_KEY_ID']=token['Credentials']['AccessKeyId']
    os.environ['AWS_SECRET_ACCESS_KEY']=token['Credentials']['SecretAccessKey']
    os.environ['AWS_SESSION_TOKEN']=token['Credentials']['SessionToken']
else:
    log.info('Removing AWS credentials from environment variables')
    del os.environ['AWS_ACCESS_KEY_ID']
    del os.environ['AWS_SECRET_ACCESS_KEY']
    del os.environ['AWS_SESSION_TOKEN']

# Give the user some basic info as to what has just happened
log.info('----------------------------------------------------------------')
log.info('Your new access key pair has been stored in the AWS configuration file {0} under the [{1}] profile.'.format(filename, args.profile))
log.info('Note that it will expire at {0}.'.format(token['Credentials']['Expiration']))
log.info('After this time, you may safely rerun this script to refresh your access key pair.')
log.info('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile {0} ec2 describe-instances).'.format(args.profile))
log.info('----------------------------------------------------------------')
print('...success')
