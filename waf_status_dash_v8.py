import requests
import json
import pandas as pd
import re
import os
import xlsxwriter
import socket
import time
import csv
import numpy
import sys
import base64
from base64 import b64decode as deco
from multiprocessing import Process, Manager, Pool, cpu_count

import smtplib,ssl
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.utils import formatdate
from email import encoders
from email.utils import COMMASPACE, formatdate

#need list with all the ips and some file to store password
#Initial Key
#urls
# ip = ['10.146.4.15', '172.20.107.14']
# ip = ['10.146.4.15']
###################################################################
base_dir = os.path.dirname(os.path.abspath(__file__))
sub_output_dir = base_dir + '/outputs'
input_dir = base_dir + '/inputs'
###################################################################
if not os.path.exists(sub_output_dir):
    os.makedirs(sub_output_dir)
if not os.path.exists(input_dir):
    os.makedirs(input_dir)
# input_ips = input_dir + '/waf_ip.txt'
# ips = open(input_ips, 'r')
# ips = ips.read()
# ips = ips.strip().splitlines()
day = time.strftime('%b_%d_%y')
waf_details = input_dir + '/waf_details.csv'
vip_codes = input_dir + '/waf_vip_codes.csv'
waf_det_df = pd.read_csv(waf_details)
vip_codes_df = pd.read_csv(vip_codes)
vip_codes_df = vip_codes_df.set_index('Code')
waf_details_ip = waf_det_df['IP'].to_list()
waf_det_df = waf_det_df.set_index('IP')
csv_file = sub_output_dir + '/waf_stat_report_' + day + '.csv'

sec_path = b'L2FwcC9zaWVfcHJvamVjdHMvc2llX3NlYw=='
secr_path = (base64.b64decode(sec_path)).decode('utf-8')
sys.path.insert(1, secr_path)
from sie_get_secrets_waf import *
waf_uname = get_sec(waf_uname)
waf_pass = get_sec(waf_pass)

def sendMail(sfrom, to, subject, text, files=[]):
    # assert type(to)==list
    # assert type(files)==list
    
    msg = MIMEMultipart()
    msg['To'] = COMMASPACE.join(to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    
    msg.attach( MIMEText(text) )
    
    for file in files:
        part = MIMEBase('application', "octet-stream")
        part.set_payload( open(file,"rb").read() )
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"'
                       % os.path.basename(file))
        msg.attach(part)
    
    server = smtplib.SMTP('mailrelay.comcast.com')
    server.starttls()
    server.sendmail(sfrom, to, msg.as_string())
    
    print ('Done')
    
    server.quit()

def array_chk(a=[]):
    return numpy.array(a)

def get_waf_details(ns, ipd, ip):
# def get_waf_details(ip):
    # h = socket.gethostbyaddr(ip)
    # h = h[0]
    # hostname = re.search('(.*)\.comcast\.net',h)
    # hostname = hostname.group(1)
    df1 = ns.df1
    hostname = df1.loc[ip]['Name']
    datacenter = df1.loc[ip]['DataCenter']
    df2 = ns.df2
    #VIP
    url_list_vip = 'https://' + ip + '/mgmt/tm/ltm/virtual?expandSubcollections=true'
    #ASM
    url_list_asm = 'https://' + ip + '/mgmt/tm/asm/policies'
    vip = requests.get(url_list_vip, auth=(waf_uname, waf_pass), verify=False)
    waf = requests.get(url_list_asm, auth=(waf_uname, waf_pass), verify=False)
    vip_d = vip.json()
    waf_d = waf.json()
    vip_d = vip_d['items']
    if type(waf_d) == type({}):
        waf_d = waf_d['items']
    else:
        pass
    vip_cl = ['name', 'destination', 'enabled', 'description', 'rules', 'profilesReference']
    waf_cl = ['name', 'virtualServers', 'active', 'createdDatetime', 'versionLastChange', 'versionDatetime', 'type', 'creatorName', 'enforcementMode']
    vip_df = pd.DataFrame(vip_d)
    waf_df = pd.DataFrame(waf_d)
    vip_df = vip_df[vip_cl]
    vip_df['vip_env'] = 'unknown'
    vip_df['vip_dport'] = numpy.NaN
    vip_df['vip_http_redirect'] = numpy.NaN
    vip_df['vip_create_date'] = numpy.NaN
    vip_df['vip_http_profile'] = 'http_profile'
    vip_df['vip_ssl_cert'] = 'ssl_cert'
    # print(vip_df)
    if len(waf_df) <= 1:
        fin_waf_df = pd.DataFrame([['not_available', 'not_available', 'not_available', 'not_available', 'not_available', 'not_available', 'not_available', 'not_available', 'not_available']], columns=['name', 'virtualServers', 'active', 'createdDatetime', 'versionLastChange', 'versionDatetime', 'type', 'creatorName', 'enforcementMode'])
    else:
        waf_df = waf_df[waf_cl]
    # print(waf_df)
    temp_waf_df = pd.DataFrame([['test_name', 'test_vip', 'test_active', 'test_createdDatetime', 'test_versionLastChange', 'test_versionDatetime', 'test_creatorName', 'test_enforcementMode']], columns=['name', 'virtualServers', 'active', 'createdDatetime', 'versionLastChange', 'versionDatetime', 'creatorName', 'enforcementMode'])
    
    for i in range(len(waf_df)):
        stype = waf_df.loc[i]['type']
        if stype == 'parent':
            continue
        a = waf_df.loc[i]['virtualServers']
        name = waf_df.loc[i]['name']
        active = waf_df.loc[i]['active']
        # print(active)
        # print(type(active))
        if active == True:
            active = 'Enabled'
        elif active != True:
            active = 'Disabled'
        createdDatetime = waf_df.loc[i]['createdDatetime']
        x = re.search('(.*)T\d+\:',createdDatetime)
        createdDatetime = x.group(1)
        versionLastChange = waf_df.loc[i]['versionLastChange']
        versionDatetime = waf_df.loc[i]['versionDatetime']
        x = re.search('(.*)T\d+\:',versionDatetime)
        versionDatetime = x.group(1)
        creatorName = waf_df.loc[i]['creatorName']
        enforcementMode = waf_df.loc[i]['enforcementMode']
        # print(array_chk(a).size)
        if array_chk(a).size > 1:
            pass
        else:
            if ((pd.isna(a)) or (len(a) == 0)):
                # print('skipping')
                continue
        for vip in a:
            s = re.search('\/Common\/(.*)', vip)
            s = s.group(1)
            temp_df = pd.DataFrame([[name, s, active, createdDatetime, versionLastChange, versionDatetime, creatorName, enforcementMode]], columns=['name', 'virtualServers', 'active', 'createdDatetime', 'versionLastChange', 'versionDatetime', 'creatorName', 'enforcementMode'])
            temp_waf_df = temp_waf_df.append(temp_df, ignore_index=True)
    fin_waf_df = temp_waf_df.drop([0])
    fin_waf_df = fin_waf_df.reset_index()
    
    for i in range(len(vip_df)):
        a = vip_df.loc[i]['destination']
        s = re.search('\/Common\/(.*)', a)
        s = s.group(1)
        vip_df.loc[i, 'destination'] = s
        b = vip_df.loc[i]['enabled']
        if b == True:
            vip_df.loc[i, 'enabled'] = 'Enabled'
        elif b != True:
            vip_df.loc[i, 'enabled'] = 'Disabled'
        dport = re.search('.*[:.](\d+)$', s)
        if dport.group(1):
            dport = dport.group(1)
            vip_df.loc[i, 'vip_dport'] = dport
        vip_name = vip_df.loc[i]['name']
        vip_env = re.search('.*([pstdqi])\_(v6\_)*\d+', vip_name)
        if vip_env != None:
            if vip_env.group(1):
                vip_env = vip_env.group(1)
                if vip_env in df2.index:
                    vip_df.loc[i, 'vip_env'] = df2.loc[vip_env]['Description']
        if vip_df.loc[i].isnull()['rules'] == False:
            v_rule = vip_df.loc[i]['rules'][-1]
            if 'https_redirect' in v_rule:
                vip_df.loc[i, 'vip_http_redirect'] = 'Enabled'
        if vip_df.loc[i].isnull()['description'] == False:
            vip_desc = vip_df.loc[i]['description']
            vip_cr_date = re.search('^.*?(\d+\-\d+\-\d+).*$', vip_desc)
            if vip_cr_date != None:
                if vip_cr_date.group(1):
                    vip_cr_date = vip_cr_date.group(1)
                    vip_df.loc[i, 'vip_create_date'] = vip_cr_date
        vip_prof = vip_df.loc[i]['profilesReference']
        vip_prof = vip_prof['items']
        vip_prof_l = []
        vip_ssl_l = []
        for x in vip_prof:
            if 'http' in x['name']:
                vip_prof_l.append(x['name'])
            if 'clientssl' in x['name']:
                vip_ssl_l.append(x['name'])
        vip_df.at[i, 'vip_http_profile'] = vip_prof_l
        vip_df.at[i, 'vip_ssl_cert'] = vip_ssl_l
    vip_df = vip_df.rename(index=str, columns={"name":"vip", "destination":"ip", "enabled":"vip_status", "vip_dport":"dst_port", "vip_http_redirect":"https_redirect"})
    fin_waf_df = fin_waf_df.rename(index=str, columns={"name":"waf_policy", "virtualServers":"vip", "active":"waf_status", "createdDatetime":"waf_create_date", "versionDatetime":"last_version_date", "versionLastChange": "last_version_chg", "enforcementMode":"waf_mode", "creatorName":"waf_created_by"})
    fin_df = vip_df.merge(fin_waf_df, on='vip', how='left')
    fin_df['lb_name'] = hostname
    fin_df['data_center'] = datacenter
    fin_df = fin_df[['data_center', 'lb_name', 'vip', 'vip_env', 'ip', 'dst_port', 'vip_status', 'https_redirect', 'vip_http_profile', 'vip_ssl_cert', 'vip_create_date', 'waf_policy', 'waf_status', 'waf_mode', 'description', 'waf_create_date', 'waf_created_by', 'last_version_date', 'last_version_chg']]
    # print(fin_df)
    ipd[hostname] = fin_df

def manager(df1, df2, ips = []):
    # print('Manager')
    manager = Manager()
    ipd = manager.dict()
    ns = manager.Namespace()
    ns.df1 = df1
    ns.df2 = df2
    pool = Pool(cpu_count())
    for ip in ips:
        pool.apply_async(get_waf_details, args=(ns,ipd,ip) )
    pool.close()
    pool.join()
    return dict(ipd)

	
if __name__ == "__main__":
    # waf_results = manager(ips)
    waf_results = manager(waf_det_df, vip_codes_df, waf_details_ip)
    print(waf_results)
    with open(csv_file, 'a') as f:
        f.write('data_center,lb_name,vip,vip_env,ip,dst_port,vip_status,https_redirect,vip_http_profile,vip_ssl_cert,vip_create_date,waf_policy,waf_status,waf_mode,description,waf_create_date,waf_created_by,last_version_date,last_version_chg')
        f.write('\n')
    for k in waf_results:
        waf_results[k].to_csv(csv_file, mode='a', index=False, header=False, line_terminator='\n')
    sendMail('no_reply@siewaf.comcast.net', ['pujith_somasundaram@comcast.com', 'maz_mavvaj@comcast.com', 'Sharbel_Semaan@comcast.com', 'Theodore_Hong@cable.comcast.com', 'Maheshumanath_Gopalakrishnan@comcast.com', 'JoySharon_Jayaraj@comcast.com', 'Viswanath_Amaranathan@comcast.com', 'Esteban_Ramirez2@comcast.com'], 'SIE WAF Report: '+day, 'Hi,\nPlease find attached WAF status report.', [csv_file])
    # sendMail('no_reply@siewaf.comcast.net', ['pujith_somasundaram@comcast.com'], 'SIE WAF Report: '+day, 'Hi,\nPlease find attached WAF status report.', [csv_file])
    print('Done')
    # get_waf_details('10.146.4.15')