#coding:utf-8
'''
Created on 2017/11/9

@author: gy071089
'''

import requests
import json
from requests.packages import urllib3
import time

url = 'https://xx.xx.xx.xx:8834'
verify = False
token = ''
Access_Key = 'access_key'
Secret_Key = 'security_key'


def build_url(resource):
    return '{0}{1}'.format(url, resource)

def connect_without_resp(method, resource, data=None):
    headers = {
               'content-type': 'application/json',
               'X-ApiKeys':'accessKey = Access_Key;secretKey = Secret_Key',
               }
    if data != None:
        data = json.dumps(data)
    urllib3.disable_warnings()
    if method == 'POST':
        r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'PUT':
        r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'DELETE':
        r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
    else:
        r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)
    
    # Exit if there is an error.
    if r.status_code != 200:
        e = r.json()
        print(e)
        #sys.exit()
    if 'download' in resource:
        return r.content
    else:
        return "Finish"

def connect(method, resource, data=None):

    headers = {
               'content-type': 'application/json',
               'X-ApiKeys':'accessKey = Access_Key;secretKey = Secret_Key',
               }
    if data != None:
        data = json.dumps(data)
    urllib3.disable_warnings()
    if method == 'POST':
        r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'PUT':
        r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'DELETE':
        r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
    else:
        r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)
    
    # Exit if there is an error.
    if r.status_code != 200:
        e = r.json()
        print(e)
        #sys.exit()
        
    if 'download' in resource:
        return r.content
    else:
        return r.json()

def get_policies():
    """
    获取自定义的规则列表
    """
    data = connect('GET', '/policies')
    return dict((p['name'], p['template_uuid']) for p in data['policies'])
    

def add(name, desc, targets, uuid):
    """
    添加扫描
    """
    scan = {
        'uuid': uuid,
        'settings': {
            'name': name,
            'description': desc,
            'text_targets': targets
        }
    }
    data = connect('POST', '/scans', scan)
    return data['scan']

def launch(sid):
    """
    启动扫描
    """
    data = connect('POST', '/scans/{0}/launch'.format(sid))
    return data['scan_uuid']


def stop(sid):
    """
    停止扫描
    """
    data = connect_without_resp('POST', '/scans/{0}/stop'.format(sid))
    return data

def pause(sid):
    """
    暂停扫描
    """
    data = connect_without_resp('POST', '/scans/{0}/pause'.format(sid))
    return data

def resume(sid):
    """
    恢复扫描
    """
    data = connect_without_resp('POST', '/scans/{0}/resume'.format(sid))
    return data

def details(sid):
    """
    获取扫描结果
    """
    data = connect('GET', '/scans/{0}'.format(sid))
    return data

def get_plugin_output(sid,host_id,plugin_id):
    """
    获取漏洞详细信息
    """
    data = connect('GET','/scans/{0}/hosts/{1}/plugins/{2}'.format(sid,host_id,plugin_id))
    return data


if __name__ == '__main__':
    policies = get_policies()
    pid = policies['Advanced Scan']
    scan = add('test','this is a test','xx.xx.xx.xx',pid)
    scan_id=scan['id']
    print(scan_id)
    scan_uuid=launch(scan_id)
    #res=pause(sid)
    #res=resume(sid)
    while True:
        res = details(scan_id)
        if res['info']['status'] == 'completed':
            res = details(scan_id)['vulnerabilities']
            break
        time.sleep(300)
        
    print(res)
    


