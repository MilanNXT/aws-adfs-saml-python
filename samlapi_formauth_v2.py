#!/usr/bin/env python3
# https://aws.amazon.com/blogs/security/how-to-implement-federated-api-and-cli-access-using-saml-2-0-and-ad-fs/
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

parser = argparse.ArgumentParser(prog='samlapi_formauth2', description='Obtain AWS credentials using ADFS Saml assertion and store into shared credential file. Python 3 version.',formatter_class=argparse.ArgumentDefaultsHelpFormatter)
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
parser.add_argument("-i", "--silent", dest="silent", default=False, action="store_true", help="Supress all inputs. If parameters not provided script will fail")
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

log.info("Using following input parameter values:")
log.info(">> profile: [%s]", args.profile)
log.info(">> region: [%s]", args.region)
log.info(">> output: [%s]", args.output)
log.info(">> role arn: [%s]", args.rolearn)
log.info(">> aws config file: [%s]", args.awsconfigfile)
log.info(">> idp entry url: [%s]", args.idpentryurl)
log.info(">> username: [%s]", args.username)
log.info(">> session duration: [%s]", args.sessionduration)
log.info(">> proxy: [%s]", args.proxy)
log.info(">> no ssl verification: [%s]", args.nosslverification)
log.info(">> force: [%s]", args.force)
log.info(">> set env vars: [%s]", args.setenvvars)
log.info(">> store as default: [%s]", args.storeasdefault)

##########################################################################
# Variables

username = args.username.strip()
password = args.password.strip()
rolearn = args.rolearn.strip()
region = args.region.strip()
output = args.output.strip()
profile = args.profile.strip()
# proxy details
proxy = {}; proxy['https'] = args.proxy

##########################################################################

# Test existing credentials
if not args.force:
    ext = False
    try:
        log.info('Validating credential from profile [{0}]'.format(profile))
        s3conn = boto3.Session(
            profile_name = profile,
            region_name = region
        )
        s3 = s3conn.resource('s3',config=Config(proxies=proxy))
        buckets = [bucket.name for bucket in s3.buckets.all()]
        print('Valid credential are still available. No need to refresh. Use --force to force refresh')
        ext = True
    except:
        log.info('Credentials expired, processing to refresh...')
        ext = False

    if ext:
        sys.exit(0)

if 'USERDOMAIN' in os.environ:
    currentuser  =  getpass.getuser() + '@' + os.environ['USERDOMAIN']
else:
    currentuser  =  getpass.getuser()

# Get the federated credentials from the user
if username in (None, '') or not username.strip():
    print("Input your CORP domain credentials:")
    if not args.silent:
        username = input("Username [{0}]: ".format(currentuser))
    else:
        log.warning('silent mode enforced, skiping username input...')
    if username in (None, '') or not username.strip():
        username = currentuser.strip()

if password in (None, '') or not password.strip():
    if not args.silent:
        password = getpass.getpass("Password for [{0}]:".format(username))
    else:
        log.warning('silent mode enforced, skiping password input...')

if username in (None, '') or not username.strip():
    log.error('empty username. it must be provided...')
    quit_message()
    sys.exit(1)

log.info("Using username: [{0}]".format(username))

# Initiate session handler
session = requests.Session()

payload = {}
payload['username']=username
payload['password']=password
payload['authentication']='FormsAuthentication'

# Programmatically get the SAML assertion
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
authmetod = ''
authcontext = ''
# Look for the SAMLResponse attributes
soup = BeautifulSoup(response.text,'html.parser')
for inputtag in soup.find_all('input'):
    if(inputtag.get('name') == 'SAMLResponse'):
        samlresponseencoded = inputtag.get('value')
    if(inputtag.get('name') == 'AuthMethod'):
        authmetod = inputtag.get('value')
    if(inputtag.get('name') == 'Context'):
        authcontext = inputtag.get('value')

# if MFA is required fail and exit
if authmetod in (None, '') or not authmetod.strip():
    if authmetod == 'AzureMfaServerAuthentication':
        log.info('Authentication: {0}'.format(authmetod))
        log.error('MFA authorization required...')
        quit_message()
        sys.exit(1)

# Better error handling is required for production use.
if (samlresponseencoded == ''):
    log.error('No valid ADFS assertion received, please try again...')
    log.error('Suggestion: Check your username and password or supply alternative credentials.')
    quit_message()
    sys.exit(1)

# Debug only
# print(base64.b64decode(assertion))

# Parse the returned assertion and extract the authorized roles
awsroles = []
samlsessionduration = '0'
samlrolesessionname = 'not available'
samlresponse = ET.fromstring(base64.b64decode(samlresponseencoded))
for saml2attribute in samlresponse.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            try:
                awsroles.append(saml2attributevalue.text.split(','))
            except:
                info.warning('SAML Role attribute [{0}] has incorect format, ignoring. Must be [principal_role,role_to_assume]'.format(saml2attributevalue.text))
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
    sys.exit(1)

# if rolearn parameter provided  try to find in saml response
selectedroleindex = -1
if not(rolearn in (None, '') or not rolearn.strip()):
    log.info("Looking for role [{0}] in SAML response...".format(rolearn))
    for i,samlroles in enumerate(awsroles):
      selectedroleindex = i
      if rolearn == samlroles[1]:
        log.info("...role found and selected")
        break
    if (selectedroleindex == len(awsroles)-1) and (rolearn != awsroles[selectedroleindex][1]):
        selectedroleindex = -1
        log.info("...not found")

if args.silent:
    if selectedroleindex == -1:
        log.error('Silent mode enforced. No Role Arn hasbeen provided nor selected')
        quit_message()
        sys.exit(1)
else:
    if selectedroleindex == -1:
        if len(awsroles) > 1:
            i = 0
            print("Please choose the role you would like to assume:")
            for samlroles in awsroles:
                print ('[', i, ']: ', samlroles[1])
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
                    sys.exit(1)
            else:
                log.error('Invalid index. Must be number between 0 nad {0}, please try again...'.format(len(awsroles)-1))
                quit_message()
                sys.exit(1)
        else:
            log.warning("only single role returned which does not match one provided as parameter, assuming anyway...") if not(rolearn in (None, '') or not rolearn.strip()) else None
            selectedroleindex = 0

# Select Principal Role and Role to assume
selectedprincipalarn, selectedrolearn = awsroles[selectedroleindex]

# Use returned SAML assertion to get an AWS STS token
downgrade = False
try:
    log.info('Assuming role [{0}]...'.format(selectedrolearn))
    token = boto3.client('sts',config=Config(proxies=proxy,region_name=region)).assume_role_with_saml(
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
    downgrade = True

# if previous call failed then try to call again with downgraded session duration
if downgrade:
    log.warning('Trying again with session duration downgrade to 28800 seconds...')
    try:
        log.info('Assuming role [{0}]...'.format(selectedrolearn))
        token = boto3.client('sts',config=Config(proxies=proxy,region_name=region)).assume_role_with_saml(
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
        sys.exit(1)

# Write the AWS STS token into the AWS credential file
home = os.path.expanduser("~")
filename = home + args.awsconfigfile

# Read in the existing config file
config = configparser.RawConfigParser()
config.read(filename)

# Put the credentials into saml profile
if not config.has_section(profile):
    config.add_section(profile)
config.set(profile, 'output', output)
config.set(profile, 'region', region)
config.set(profile, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
config.set(profile, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
config.set(profile, 'aws_session_token', token['Credentials']['SessionToken'])

# Put the credentials into default profile
if args.storeasdefault:
    if not config.has_section('default'):
        config.add_section('default')
    config.set('default', 'output', output)
    config.set('default', 'region', region)
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
    if 'AWS_ACCESS_KEY_ID' in os.environ:
        del os.environ['AWS_ACCESS_KEY_ID']
    if 'AWS_SECRET_ACCESS_KEY' in os.environ:
        del os.environ['AWS_SECRET_ACCESS_KEY']
    if 'AWS_SESSION_TOKEN' in os.environ:
        del os.environ['AWS_SESSION_TOKEN']
# Give the user some basic info as to what has just happened
log.info('----------------------------------------------------------------')
log.info('Your new access key pair has been stored in the AWS configuration file {0} under the [{1}] profile.'.format(filename, profile))
log.info('Note that it will expire at {0}.'.format(token['Credentials']['Expiration']))
log.info('After this time, you may safely rerun this script to refresh your access key pair.')
log.info('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile {0} ec2 describe-instances).'.format(profile))
log.info('----------------------------------------------------------------')
print('...success')
