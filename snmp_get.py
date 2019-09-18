import logging
import json
import traceback
from time import sleep
from pysnmp.hlapi import getCmd, bulkCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
from ipaddress import ip_address
from datetime import datetime
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool
from tqdm import tqdm
result_dict = {}


def snmp_getcmd (community, ip, port, OID):
    return (getCmd(SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((ip, port), timeout=0.9, retries=0),
                        ContextData(),
                        ObjectType(ObjectIdentity(OID))))

def snmp_get_next (community, ip, port, OID):
    errorIndication, errorStatus, erroreIndex, varBinds = next(snmp_getcmd(community, ip, port, OID))
    for name, val in varBinds:
        if (val.prettyPrint()) == '' or (val.prettyPrint()) == 'No Such Object currently exists at this OID':
            return None
        if isinstance((val.prettyPrint()), str):
            return (val.prettyPrint())
        else:
            return None

def white_list():
    conrol_vlan_list = [100,200,300,400,500,600]
    user_vlan_list= [x for x in range(1000, 1500)]
    whitelist = conrol_vlan_list + user_vlan_list
    return whitelist


def check_ip(ip):
    try:
        ip_address(ip)
    except ValueError:
        return False
    else:
        return True

def get_func(ip):
    if check_ip(ip):
        port_dict = {}
        for commut_port in range(1, 28 + 1):
            try:
                port_dict[commut_port] = (snmp_get_next(community, ip, snmp_port, '{}{}'.format(OID, str(commut_port))))
            except:
                logger.error('Fail in get_func() ip: {} traceback:{}'.format(ip, traceback.format_exc()))
                bad_ips.append(ip)
        if port_dict:
            result_dict[ip] = port_dict
            #print('============={}===============\n{}\n{}\n'.format(datetime.now(), ip, json.dumps(port_dict)))
    else:
        #print('BAD IP: {}'.format(ip))
        bad_ips.append(ip)
        logger.error('BAD IP: {} traceback:{}'.format(ip, traceback.format_exc()))
    pbar.update(1)



if __name__ == "__main__":
    file_name = 'DES-1210-28_ME_B2.txt'
    OID = '.1.3.6.1.2.1.17.7.1.4.5.1.1.'
    community = 'holding08'
    snmp_port = 161
    ips = []
    bad_ips = []
    wh_list = white_list()
    ################################
    # Logger settings
    logger = logging.getLogger("MAIN_APP")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler("{}.log".format(file_name))
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    #################################
    with open (file_name, 'r') as f:
        lines = f.readlines()
        for line in lines:
            ips.append(line.rstrip())
    pbar = tqdm(total=len(ips))
    pool = ThreadPool(4)
    pool.map(get_func, ips)
    pool.close()
    pool.join()
    pbar.close()
    if result_dict:
        with open (file_name + '.result.txt', 'w') as f:
            f.write(json.dumps(result_dict))
            print('WRITE RESULT is OK')
    if bad_ips:
        with open (file_name + '.bad_ip_list.txt', 'w') as f:
            for i in bad_ips:
                f.write(i + '\n')
    print('WRITE BAD is OK')


