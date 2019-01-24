#! /usr/bin/env python3
#title           :sgws_create_user.py
#description     :Creates a local user in a StorageGRID Webscale Tenancy 
#author          :wilsg@netapp.com
#date            :20180802
#version         :1.0
#usage           :./sgws_create_user.py -a [SGWS TENANT ID] -u [TENANT ROOT USERNAME] -p [TENANT ROOT PASSWORD] -s [NEW USERNAME] -g [GID OF GROUP] -f [FULL NAME] -j [NEW PASSWORD]
#notes           :
#python_version  :2.7.x
#==============================================================================

import json
import requests
import argparse
import logging
import sys
import urllib3
import urllib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

parser = argparse.ArgumentParser(description='Creates a local user in a StorageGRID Webscale Tenancy.')
parser.add_argument('-a','--account-id', help='SGWS Tenant Account ID', required=True)
parser.add_argument('-u','--username', help='Tenant Root Username', required=True)
parser.add_argument('-p','--password', help='Tenant Root Password', required=True)
parser.add_argument('-s','--newuser', help='New username eg. user\johndoe', required=True)
parser.add_argument('-g','--group', help='Destination Group ID', required=True)
parser.add_argument('-f','--newfullname', help='New full name eg. "John Doe"', required=True)
parser.add_argument('-j','--newpassword', help='New password for account', required=True)
parser.add_argument('-l','--api-url', help='API URL', default='https://10.10.200.91/api/v2', required=False)

try:
    args = parser.parse_args()
except:
    parser.print_help()
    sys.exit(99)


##### PROCEDURE TO AUTOMATE #####
#
# Assumptions:
#
#

base_url = args.api_url
ssl_verify = False

headers = {}
headers['Content-Type'] = "application/json"
headers['Accept'] = "application/json"

query_string = {}

payload = {}
payload['accountId'] = args.account_id
payload['username'] = args.username
payload['password'] = args.password

json_payload = json.dumps(payload)

#
# Authenticate and get auth tokens we use for API Calls 
#

try:
    response = requests.post("{}".format(base_url) + '/authorize', headers=headers, data=json_payload, verify=ssl_verify)
    response.raise_for_status()
    authtoken = response.json()['data']
    headers["Authorization"] = str.format("Bearer %s" % (str(authtoken)))
    print ("Auth Token: ", authtoken)
except Exception as e :
    print("Auth error: {}".format(e))

#
# Create User 
# 

# Read in args and define 
newfullname = args.newfullname
newusername = args.newuser
group = args.group

payload1 = {}
payload1['fullName'] = newfullname
payload1['memberOf'] = [group]
payload1['disable'] = False
payload1['uniqueName'] = newusername

json_payload1 = json.dumps(payload1)

print ("payload1", json_payload1)

response = requests.post('https://10.10.200.91/api/v2/org/users', headers=headers, data=json_payload1, verify=ssl_verify)
print (response.text)

#
# Create Set of new Keys
#
# 1. lookup username just created and get UID and assign it to shortid

shortname = newusername.split('/')[-1]

print ("Short Username: ", shortname)

response1 = requests.get("{}".format(base_url) +'/org/users/user/'+ shortname, headers=headers, verify=ssl_verify)
response.raise_for_status()
data3 = response.json()['data']['id']
print ("User Id:", data3)
shortid = data3
#
# Create New Password
#
newpassword = args.newpassword
print ("New Password: ", newpassword)

data4 = '{\n  "password": "test1234",\n  "currentPassword": ""\n}'
response = requests.post("{}".format(base_url) +'/org/users/' + shortid + '/change-password', headers=headers, data=data4, verify=ssl_verify )
#
# Response if successful 204 
print ("Setting Password of " + shortname + " "+ shortid)
print (response.text)

# 
# Create Initial Secret Keys
#  Valid for one year
#

data5 = '{\n  "expires": "2019-12-04T00:00:00.000Z"\n}'
response = requests.post("{}".format(base_url) +'/org/users/' + shortid + '/s3-access-keys', headers=headers, data=data5, verify=ssl_verify )
response.raise_for_status()
accesskey = response.json()['data']['accessKey']
secretaccesskey = response.json()['data']['secretAccessKey']
print ("Access Key: ", accesskey)
print ("Secret Access Key: ", secretaccesskey) 
