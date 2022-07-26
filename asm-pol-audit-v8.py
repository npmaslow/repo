# V8 - added validation of specific signature sets and XML
# V6 - added elements with signatures overriden (URL, Parameters, Headers)
# V4 - added learning for the policies
# V2 - added skiping if the device is in standby - added number of signature ready to be enforced
import argparse
import csv
import datetime
import getpass
import json
import os
import re
import requests
import urllib3

# global variable - file to save data
dt = datetime.datetime.today()
filename = "asm-policies-audit-%02d-%02d-%02d-%02d%02d.csv" %(dt.month,dt.day,dt.year,dt.hour,dt.minute)

def get_token(b, url_base, creds):
    url_auth = '%s/shared/authn/login' % url_base
    try:
        payload = {}
        payload['username'] = creds[0]
        payload['password'] = creds[1]
        payload['loginProviderName'] = 'tmos'
        token = b.post(url_auth, json.dumps(payload)).json()['token']['token']
    except:
        token = '' 
    return token

def audit_asm_policies_high_level(device):

    print('Working on ASM policies for device %s' % device)
 
    # filter policies - obtains policy ID, name, enforcement mode, has parent, type and parent policy name
    url_base_asm = 'https://%s/mgmt/tm/asm/policies/?$select=id,name,enforcementMode,hasParent,type,parentPolicyName' % device
    bigip = requests.session()
    bigip.headers.update({'Content-Type': 'application/json'})
    bigip.headers.update({'X-F5-Auth-Token': token})
    bigip.verify = False
    bigip.auth = None
    
    r = bigip.get(url_base_asm)
    json_data = r.json()

    # iterate over the data obtained and performed specific policy lookup (e.g. how many signatures are in staging)
    for i in json_data['items']:
        if( i['type']=='parent'):
            continue
        if( i['hasParent'] == False):
            i['parentPolicyName'] = 'N/A'
        if( i['name'].endswith('p' ) ):
            env = 'Prod'
        else:
            env = 'Non-prod'
        policies_data = [ device, i['name'], env, i['enforcementMode'], i['hasParent'], i['parentPolicyName']]
        policy_data = audit_asm_policy_high_level(i['id'])
        policies_data = policies_data + policy_data 
        asm_policy_high_level_save(policies_data)

def audit_asm_policy_high_level(policy_id):

    # filter data specific for each policy
    url_sig_sta = 'https://%s/mgmt/tm/asm/policies/%s/signatures?$filter=performStaging+eq+true&$top=1&$select=totalItems' % (device,policy_id)
    url_par_sta = 'https://%s/mgmt/tm/asm/policies/%s/parameters?$filter=performStaging+eq+true&$top=1&$select=totalItems' % (device,policy_id)
    url_url_sta = 'https://%s/mgmt/tm/asm/policies/%s/urls?$filter=performStaging+eq+true&$top=1&$select=totalItems' % (device, policy_id)
    url_sig_ready = 'https://%s/mgmt/tm/asm/policies/%s/signatures?$filter=hasSuggestions+eq+false+AND+wasUpdatedWithinEnforcementReadinessPeriod+eq+false+and+performStaging+eq+true&$top=1' % (device,policy_id)
    url_sug = 'https://%s/mgmt/tm/asm/policies/%s/suggestions?$top=1&$select=totalItems' % (device, policy_id)
    url_learn = 'https://%s/mgmt/tm/asm/policies/%s/policy-builder?$select=learningMode,enableTrustedTrafficSiteChangeTracking' % (device, policy_id)
    url_ov1 = 'https://%s/mgmt/tm/asm/policies/%s/parameters/?$select=name,signatureOverrides' % (device, policy_id)
    url_ov2 = 'https://%s/mgmt/tm/asm/policies/%s/urls?$select=name,signatureOverrides' % (device, policy_id)
    url_ov3 = 'https://%s/mgmt/tm/asm/policies/%s/headers?$select=name,signatureOverrides' % (device, policy_id)
    #url_stgbinary = 'https://%s/mgmt/tm/asm/policies/%s/signatures?filter=performStaging' % (device,policy_id)
    url_sets = 'https://%s/mgmt/tm/asm/policies/%s/signature-sets/' % (device,policy_id)
    #url_redirprotect = 'https://%s/mgmt/tm/ltm/profile/http/' % (device,profile_id)
    url_xmlmask = 'https://%s/mgmt/tm/asm/policies/%s/xml-profiles/' % (device,policy_id)
    #url_httpcompliance = 'https://%s/mgmt/tm/security/' % (device,profile_id)

    bigip = requests.session()
    bigip.headers.update({'Content-Type': 'application/json'})
    bigip.headers.update({'X-F5-Auth-Token': token})
    bigip.verify = False
    bigip.auth = None

    policy_data = []

    # learning mode
    r = bigip.get(url_learn)
    policy_data.append(r.json()['learningMode']) 
    if r.json()['learningMode']=='disabled':
        policy_data.append('N/A')
    else:
        policy_data.append(r.json()['enableTrustedTrafficSiteChangeTracking'])  

    # total signatures in staging, parameters, URL and signatures ready to be enforce
    r = bigip.get(url_sig_sta)
    policy_data.append(r.json()['totalItems'])
    
    r = bigip.get(url_sig_ready)
    policy_data.append(r.json()['totalItems'])
    
    r = bigip.get(url_par_sta)
    policy_data.append(r.json()['totalItems'])
    
    r = bigip.get(url_url_sta)
    policy_data.append(r.json()['totalItems'])

    r = bigip.get(url_sug)
    policy_data.append(r.json()['totalItems'])

    # check for presence of elements with signatures overriden 
    r = bigip.get(url_ov1)
    p = 0
    for i in r.json()['items']:
        # check if element exists
        if 'signatureOverrides' in i:
            # check if element is not empty
            if i['signatureOverrides']:
                for x in i['signatureOverrides']:
                    p = p + 1      
    policy_data.append(p)   

    r = bigip.get(url_ov2)
    p = 0
    for i in r.json()['items']:
        # check if element exists
        if 'signatureOverrides' in i:
            # check if element is not empty
            if i['signatureOverrides']:
                for x in i['signatureOverrides']:
                    p = p + 1
    policy_data.append(p)

    r = bigip.get(url_ov3)
    p = 0
    for i in r.json()['items']:
        # check if element exists
        if 'signatureOverrides' in i:
            # check if element is not empty
            if i['signatureOverrides']:
                for x in i['signatureOverrides']:
                    p = p + 1
    policy_data.append(p)

    # check for matching signaturesets
    r = bigip.get(url_sets)
    sigset = r.json()["items"]
    sigsetstr = json.dumps(sigset)
    #policy_data.append(sigsetstr)
    if (sigsetstr.find('Spring4Shell') != -1):
        policy_data.append('Present')
    else:
        policy_data.append('Not Present')  

    if (sigsetstr.find('Log4j') != -1):
        policy_data.append('Present')
    else:
        policy_data.append('Not Present')

    if (sigsetstr.find('comcast-lowrisk-highaccuracy') != -1):
        policy_data.append('Present')
    else:
        policy_data.append('Not Present')

    if (sigsetstr.find('comcast-mediumrisk-highaccuracy') != -1):
        policy_data.append('Present')
    else:
        policy_data.append('Not Present')

    if (sigsetstr.find('comcast-highrisk-highaccuracy') != -1):
        policy_data.append('Present')
    else:
        policy_data.append('Not Present')
    
    if (sigsetstr.find('Medium Accuracy Signatures') != -1):
        policy_data.append('Present')
    else:
        policy_data.append('Not Present')

    if (sigsetstr.find('Server Side Code Injection') != -1):
        policy_data.append('Present')
    else:
        policy_data.append('Not Present')

    if (sigsetstr.find('Server-Side Request Forgery') != -1):
        policy_data.append('Present')
    else:
        policy_data.append('Not Present')

    #XML Mask Check
    r = bigip.get(url_xmlmask)
    xmlset = r.json()["items"]
    xmlsetstr = json.dumps(xmlset)
    #policy_data.append(xmlsetstr)
    if (xmlsetstr.find('password') != -1):
        policy_data.append('password Masked')
    else:
        policy_data.append('none Masked')

    return policy_data

def asm_policy_high_level_save(data):

    # create file if it does not exist
    if(os.path.isfile(filename)==False):
        headers = ['device','policy', 'environment', 'enforcement mode','has parent','parent policy','learning mode','track site change','sig in stg','sig ready', 'params in stg','urls in stg', 'total suggestions','sig over param', 'sig over url','sig over header','Spring4Shell Set','Log4j Set','Comcast LowRisk HighAcc Set','Comcast MedRisk HighAcc Set','Comcast HighRisk HighAcc Set','MedAcc Set','SrvSide Code Inj Set','SrvSide ReqForg Set','XML Mask']
        with open(filename, mode='w') as pol_file:
            pol_file = csv.writer(pol_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            pol_file.writerow(headers)
    
    with open(filename, mode='a') as pol_file:
        pol_file = csv.writer(pol_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        pol_file.writerow(data)

def check_active(device):
    
    # obtain device name
    url_base_asm = 'https://%s/mgmt/tm/sys/global-settings?$select=hostname' % device
    bigip = requests.session()
    bigip.headers.update({'Content-Type': 'application/json'})
    bigip.headers.update({'X-F5-Auth-Token': token})
    bigip.verify = False
    bigip.auth = None
    
    r = bigip.get(url_base_asm)
    hostname = r.json()['hostname']
 
    # filter policies - obtains policy ID, name, enforcement mode, has parent, type and parent policy name
    url_base_asm = 'https://%s/mgmt/tm/cm/traffic-group/traffic-group-1/stats?$select=deviceName,failoverState' % device
    bigip = requests.session()
    bigip.headers.update({'Content-Type': 'application/json'})
    bigip.headers.update({'X-F5-Auth-Token': token})
    bigip.verify = False
    bigip.auth = None
    
    r = bigip.get(url_base_asm)
    json_data = r.json()
    
    for i in json_data['entries']:
        devices = json_data['entries'][i]['nestedStats']
        # returns similar to 
        #{'entries': {'deviceName': {'description': '/Common/bigip1.f5labs.net'}, 'failoverState': {'description': 'standby'}}}
        device = devices['entries']['deviceName']['description']
        state = devices['entries']['failoverState']['description']
        
        if (hostname in device):
            return True
         
    return False

if __name__ == "__main__":
    urllib3.disable_warnings()

    parser = argparse.ArgumentParser()

    parser.add_argument("device", help='BIG-IP devices list separated by line')
    args = vars(parser.parse_args())

    device = args['device']

    username = input('Enter your username: ') 
    password = getpass.getpass('Enter your password: ')

    with open(device,'r') as a_file:
        for line in a_file:
            device = line.strip()
            # TODO - test connectivity with each device and report on the ones failing 
            url_base = 'https://%s/mgmt' % device
            bigip = requests.session()
            bigip.headers.update({'Content-Type': 'application/json'})
            bigip.auth = (username, password)
            bigip.verify = False
            token = get_token(bigip, url_base, (username, password))
            if (not token):
                print('Unable to obtain token for device ' + device)
                continue 
            #if not check_active(device): 
            #    print('Device ' + device + ' is not active, skipping it...')
            #    continue
            audit_asm_policies_high_level(device)
    print('File saved: %s' % filename)

