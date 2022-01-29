#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys
import pwd
import ssl
import json
import base64
import socket
import argparse
import subprocess

DEPLOY_PY_VERSION       = u'21.1-58'

PY3 = sys.version_info.major == 3

if PY3:
    # python3
    import http.client as httplib
    from urllib.parse import urlencode
else:
    # python2
    import httplib
    from urllib import urlencode

# fallback to UTF-8 in case the environment does not return the encoding
py2_encoding = sys.stdin.encoding
if not PY3 and py2_encoding == None:
    py2_encoding = "UTF-8"

'''
    * These fields can be used instead of command line arguments *
'''

API_CA_CRT = u'''
-----BEGIN CERTIFICATE-----
MIIF9TCCA92gAwIBAgIEWvVuTTANBgkqhkiG9w0BAQsFADBWMRUwEwYDVQQLDAxQ
cml2WCBUTFMgQ0ExPTA7BgNVBAMMNGVjMi0zNS0xNTgtMTMzLTg1LmV1LWNlbnRy
YWwtMS5jb21wdXRlLmFtYXpvbmF3cy5jb20wHhcNMTgwNTExMTAxOTU3WhcNMzgw
NTA2MTAxOTU3WjBWMRUwEwYDVQQLDAxQcml2WCBUTFMgQ0ExPTA7BgNVBAMMNGVj
Mi0zNS0xNTgtMTMzLTg1LmV1LWNlbnRyYWwtMS5jb21wdXRlLmFtYXpvbmF3cy5j
b20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDql72jyCg2yc4C4RTR
D6vkZ4j2bdonttf56AnIISNYRUWdTIMq9/TChcsvU/uOW9ZRsYg6N5w0IPOk9dkc
VUD4swGgnxWoUszE5aAcgHJSJSSc1byvSfdrqFfdlNwbbEN4+CFNpZpGwLaKalC0
TsHvtlTdcDsrxL5hZTiximy4ijT0jQca1QFyGJFZvRrlm2TNRwraaqCHfyRk75VD
v6PAmHAJf6Jt8TWUbxGX6Pi+Mcuv1lTm/TAMI+LB+nZ4fAuVQMhR5gR7tBVyAsTG
QFzjwu+XK/q9HJWKlapGCc/q/AIfRvKKF6VcX1Fks2n/RJ0JlRkgzB+105Jp52iN
9VJu4FNMbBfOr8JU5CVttVfotTePzwRJE0zI2e7ayI9nuqoDqXMP7c2e1QNvWCJF
ijGXISUrZIIepwJyh0xLCczxPjwJvM0FgnCWXNcYHirZOG2Q5WDnHu8RfD9W489R
hFgApcbtDn9O3o7cqeJHeJukEbwLmmMsYUIHXmC/DsOgirWObpHXj0Yb4ZUJV8i/
Z7a733BErl5AEeFKZ9KQRXQeQtQkcC+SpCXKRcrCTrDoAGd0zMecyjjWB8evev9A
sC/UrOtfu9F+uW8CJ8uXMkRDyLB3fgabQnQ/uuWhopLAPpHyKDMov9G+PlLhcqQQ
Yf1zy0NVc+nX2ODZ7fvNMYeB7wIDAQABo4HKMIHHMBIGA1UdEwEB/wQIMAYBAf8C
AQEwDgYDVR0PAQH/BAQDAgIEMB0GA1UdDgQWBBSCrMXFYkmPbm91aN/AjcfE4vDk
uzCBgQYDVR0jBHoweIAUgqzFxWJJj25vdWjfwI3HxOLw5LuhWqRYMFYxFTATBgNV
BAsMDFByaXZYIFRMUyBDQTE9MDsGA1UEAww0ZWMyLTM1LTE1OC0xMzMtODUuZXUt
Y2VudHJhbC0xLmNvbXB1dGUuYW1hem9uYXdzLmNvbYIEWvVuTTANBgkqhkiG9w0B
AQsFAAOCAgEAKGARpR8oDycT640niXrwJb8A2tWsl9wePJxgaHAVeujNPFEiNZrx
Nvr8pGV3vu7Pmay3ncPzJBd9g+Xg9lu88ruPsF3qv7d0q5f3DMfHF3f56/nLlu+0
d/OjB09LuWtqOIXRGilC+jZ9eKsen2OjzDEm9dA+antaHhlV/hJY4Ii8Z8sl7CTE
MJ9jxu+rumgBgywysbQJcdabuQi4BJEf0oRt4gHRHtIxvS1zN8DWqRQg3fbXD+zp
K1F26zjk9knmZLGbZBc55T0oeVQazrJMeM0ameyB9dKaHK7w5r2oZrWAO5pKKLAn
VamOzAqmx412J3tFuCO8MKBmpzuZ78STWbn92/bJzDvUnv/MDPeWZQsjjXLR31R6
izGI/plEd8GT9QN8+dyENTpBmad0Z4wfTzKLZ95k1oO+Tz8MUHEapgTAVwIiS5UN
VcqWVRZua01X99mhvUefQjUsafov32Py90DXx8gdoYIEmR82fO+wOBH5tnFXKDfJ
zMdjUtaNE9FCd6fzt5VJiaddHIjI1I66BhJeyX7RMplxdYfUO10ZziHOKxkxcEAD
sXoutvs9t8XwbwCSqUheNwt9troD5aILnM+g/JaAmiHQxaC4RQ/KqEF4o1z5+oQy
KFRHdixnQMtLv5f6KdFWsbtbcbATAfENPpgqtbxyQUybEPUPJeCCkUA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFTjCCAzagAwIBAgIITazx7UsZ84wwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UE
AxMRUHJpdlggRXh0ZW5kZXIgQ0EwHhcNMTgwOTI0MDk1MDAyWhcNMjMwOTIzMDk1
MDAyWjAcMRowGAYDVQQDExFQcml2WCBFeHRlbmRlciBDQTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAKOxxo/YCpFEdxLgObal1QC7XnlUpe67O5+y6hsL
pcykrQfybJYc9DVMVbRtfWoselSx2fX75c4o24H47TYjcn0YNgZy17DOSweebJus
v4FJhMqRqDhZJkyq2kNYw5+SxgxX5WBao2WKwPqLRm9Bn5K3cPmHUsZTDuKI4Ifm
XQKB3Vz2Piq5mDLlV7466p8n0BB5WH091lZvi6+huocZfzxgyquMj1ak4oroynpX
KXC4DSFu+PXGpHwTRrKSnuEHBolIVOcfmOF+/29yLCZzXFBIxCFpQuKKSxRCd8JO
5w3/u46prLDkQCEhIr3s81nAd20m3PYf2VgHLqGHnfLMxxvv5YY5HP7Ykiu21API
RW5KQLXSmiXCTwjXB4zLrI4rbUFRZ7a0DmIgg9YIsRskypIlqD+8bBy1u483ZHhP
5BMhl9NsDlVm66Qv8JbH8yRrXIVJxFn82AgacsD6LyncM0ycF8XrKgmZhEkxdAam
ldPLECtxR4L8pI5bfxvkFknIF6FV8Lo4kqmaYyhxf0HbkCK8Z37qz/beEW+NlIWI
CehDN7XIe09RHUEqh0/nHigPaFz9+UuFzwQ5qUNDhdbLJTH7FdVd/HNksyASVEqv
hPAxbniY/TG9pw7Hjg4GnsOfPsjL5+SoAxvprBRrylWKcdL1LP7BUgEwztUtJnxq
BS15AgMBAAGjgZMwgZAwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8C
AQAwHQYDVR0OBBYEFO3Ob2TjuhWtsqpZ1QeGDOkCT76sMEsGA1UdIwREMEKAFO3O
b2TjuhWtsqpZ1QeGDOkCT76soSCkHjAcMRowGAYDVQQDExFQcml2WCBFeHRlbmRl
ciBDQYIITazx7UsZ84wwDQYJKoZIhvcNAQELBQADggIBAKH+FtremcnIyM1UEajn
R2S3C5jKiLdZPE0VvvgJMJeKrSIAdGb8bJoqKZzXV6W4Pl+y2YYisvRRz7f/QuXJ
ygiBaF87ecxMPlQfpH8l9HTuysYqcImUP3AIZJySIc7ryRxs3I/PUpSSo+LVtNim
zvbjZggsYgvVN/SXXoxKtZYpgpiTVPqerhVBYRnpOLBPIiLwFNasDl0yNzG9iVC4
4FCfHNJ7ikJY8NHRSAw8BHzUvqjhB/GYGlGy3YS/phakvJjzHdQ4ugpjEF/95Wbp
hozv1EcOVw6iFvmeEDSoos6mcEbQ9mYXr6L+MkiG145cFiyWoDylVxmyBSrewapV
Cn+zKKSwO69xvL1T+YzLUJOWdJQpxkg66Npjsc1iAQ2xWntT7M8cN1+ii8tEd5hH
81sf+ohW4B3D5Vh8ZSOH/mrDj8XX10jJTZWSk32OuKE71pb/DP0y82G95sziSs3N
+X56Hsu24TN6a1fLNiMQLKeefiBCPvSxu8dqDbb6ajBk+zhrMReNJdr5Xvad2OwQ
YSwxfJAfQKjBR2PcaROgYHhEhTLhinTIA8cBuNhOIjcd/FfxGXPSIpXhTs8ACw59
xKSTaJyTq5wXY5pzCyJzJSI/Pm8pXhyiwJUmbGtCzRd4IGe5C/ITv1h2pEPXPJe6
JSxF3K2guIIDU+Wok0CBa6/O
-----END CERTIFICATE-----

'''

API_HOSTNAME            = u'instance.testdrive.privx'
OAUTH_CLIENT_ID         = u'privx-external'.encode('utf8')
OAUTH_CLIENT_SECRET     = u'vrpigXa7SIGdKZtgZ1r7AQ'.encode('utf8')
API_CLIENT_ID           = u'be0c87cc-0cf4-4b77-53ac-6cd383830628'.encode('utf8')
API_CLIENT_SECRET       = u'KCmZnrYY2J6uPVKFx6N5mEtsg7+3jUT3BJxpKIYFQKYi'.encode('utf8')
API_ACCESS_GROUP_ID     = u'92e2ea11-f2fe-42a8-7fd8-f2bb4829d966'.encode('utf8')

if PY3:
    # convert back to strings
    OAUTH_CLIENT_ID = OAUTH_CLIENT_ID.decode()
    OAUTH_CLIENT_SECRET = OAUTH_CLIENT_SECRET.decode()
    API_CLIENT_ID = API_CLIENT_ID.decode()
    API_CLIENT_SECRET = API_CLIENT_SECRET.decode()
    API_ACCESS_GROUP_ID = API_ACCESS_GROUP_ID.decode()

'''
    * User editable content ends here *
'''

def normalize_ipv6(addr):
    addr = addr.strip().lower()
    try:
        a = socket.inet_pton(socket.AF_INET6, addr)
        addr = socket.inet_ntop(socket.AF_INET6, a).lower()

    except socket.error:
        return addr

    return addr

def normalize_hostname(hostname):
    scope_index = hostname.rfind('%')
    if scope_index != -1:
        hostname = hostname[:scope_index]

    return normalize_ipv6(hostname)

ORIGINAL_SSL_MATCH_HOSTNAME = ssl.match_hostname
def match_hostname(cert, hostname):
    '''
        Due to Python's ssl lib not supporting matching IPs we wrap the ssl
        lib's match_hostname and try to match also IPs.
    '''
    try:
        ORIGINAL_SSL_MATCH_HOSTNAME(cert, hostname)
    except ssl.CertificateError:
        ips = []
        dns_names = []
        san = cert.get('subjectAltName', ())
        for key, value in san:
            if key == 'IP Address':
                ips.append(normalize_ipv6(value))
            else:
                dns_names.append(value)

        hostname = normalize_hostname(hostname)
        if hostname in ips:
            return

        raise ssl.CertificateError("hostname %r does not match any of %s"
                                   % (hostname, ', '.join(ips + dns_names)))
ssl.match_hostname = match_hostname


def log(fmt_string, *args, **kwargs):
    message = fmt_string.format(*args, **kwargs)
    print('** {}'.format(message))


class CloudAPICallException(Exception):
    pass


def _call_cloud_api(hostname, endpoint, headers={}):
    conn = httplib.HTTPConnection(hostname, timeout=5)
    conn.request("GET", endpoint, headers=headers)
    resp = conn.getresponse()
    body = resp.read()

    if resp.status != 200:
        raise CloudAPICallException(
            "GET for endpoint {} returned HTTP {}: {}".format(endpoint,
                                                              resp.status,
                                                              body))
    if PY3:
        return body.decode()

    return body

def _call_cloud_api_endpoints(hostname, endpoints, headers={}):
    responses = []
    for endpoint in endpoints:
        try:
            resp = _call_cloud_api(hostname, endpoint, headers)
        except CloudAPICallException:
            # The call failed, continue.
            continue
        except Exception as exp:
            # Unexpected failure.
            raise exp
        else:
            responses.append(resp)

    return responses


AWS_API = "169.254.169.254"
GC_API = "metadata.google.internal"
GC_HEADERS = {"Metadata-Flavor": "Google"}
AZURE_API = "169.254.169.254"
AZURE_HEADERS = {"Metadata": "true"}


def get_aws_instance_id():
    return _call_cloud_api(AWS_API, "/latest/meta-data/instance-id")

def get_openstack_instance_id():
    body = _call_cloud_api(AWS_API, "/openstack/latest/meta_data.json")
    resp = json.loads(body)
    return resp['uuid']

def get_openstack_service_address():
    return _call_cloud_api(AWS_API, "/latest/meta-data/public-ipv4")

def get_openstack_instance_addresses():
    return [_call_cloud_api(AWS_API, "/latest/meta-data/public-hostname"),
            _call_cloud_api(AWS_API, "/latest/meta-data/public-ipv4")]

def get_aws_instance_addresses():
    mac_address = None
    try:
        resp = _call_cloud_api(AWS_API, "/latest/meta-data/mac")
    except CloudAPICallException:
        # The call failed, no mac address.
        pass
    except Exception as exp:
        # Unexpected failure.
        raise exp
    else:
        mac_address = resp

    endpoints = [
        "/latest/meta-data/public-hostname",
        "/latest/meta-data/public-ipv4",
        "/latest/meta-data/local-ipv4",
    ]

    if mac_address is not None:
        endpoints.append("/latest/meta-data/network/interfaces/macs/{}/ipv6s".format(mac_address))

    return _call_cloud_api_endpoints(AWS_API, endpoints)

def get_aws_service_address():
    endpoints = [
        "/latest/meta-data/public-hostname",
        "/latest/meta-data/public-ipv4",
        "/latest/meta-data/local-ipv4",
    ]

    addresses = _call_cloud_api_endpoints(AWS_API, endpoints)
    addresses = [addr for addr in addresses if addr]
    if len(addresses) == 0:
        raise CloudAPICallException("Could not resolve service address")

    return addresses[0]

def get_aws_instance_name():
    try:
        return _call_cloud_api(AWS_API, "/latest/meta-data/public-hostname")
    except:
        return _call_cloud_api(AWS_API, "/latest/meta-data/instance-id")

def get_azure_instance_addresses():
    return [_call_cloud_api(AZURE_API, "/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-08-01&format=text", AZURE_HEADERS),
            _call_cloud_api(AZURE_API, "/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2017-08-01&format=text", AZURE_HEADERS)]

def get_azure_instance_name():
    return _call_cloud_api(AZURE_API, "/metadata/instance/compute/name?api-version=2017-08-01&format=text", AZURE_HEADERS)

def get_azure_instance_id():
    return _call_cloud_api(AZURE_API, "/metadata/instance/compute/vmId?api-version=2017-08-01&format=text", AZURE_HEADERS)

def get_azure_service_address():
    return (_call_cloud_api(AZURE_API, "/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-08-01&format=text", AZURE_HEADERS) or
        _call_cloud_api(AZURE_API, "/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2017-08-01&format=text", AZURE_HEADERS))

def get_google_cloud_instance_id():
    return _call_cloud_api(GC_API, "/computeMetadata/v1/instance/id", GC_HEADERS)

def get_google_cloud_instance_addresses():
    return [
        _call_cloud_api(GC_API,
            "/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip",
            GC_HEADERS),
        _call_cloud_api(GC_API,
            "/computeMetadata/v1/instance/hostname",
            GC_HEADERS),
        _call_cloud_api(GC_API,
            "/computeMetadata/v1/instance/network-interfaces/0/ip",
            GC_HEADERS)
    ]

def get_google_cloud_service_address():
    return (_call_cloud_api(GC_API,
        "/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip",
        GC_HEADERS) or
        _call_cloud_api(GC_API,
            "/computeMetadata/v1/instance/network-interfaces/0/ip",
            GC_HEADERS))



def get_google_cloud_instance_name():
    return _call_cloud_api(GC_API, "/computeMetadata/v1/instance/name", GC_HEADERS)


def gather_parameters(args, api_client):
    service_port = 22
    if args.openstack:
        log('Getting OpenStack ID')
        instance_id = get_openstack_instance_id()
        service_address = get_openstack_service_address()
        return {"external_id": instance_id}, service_address, service_port
    elif args.aws:
        log('Getting AWS instance ID')
        instance_id = get_aws_instance_id()
        service_address = get_aws_service_address()
        return {"external_id": instance_id}, service_address, service_port
    elif args.google_cloud:
        log('Getting Google Cloud instance ID')
        instance_id = get_google_cloud_instance_id()
        service_address = get_google_cloud_service_address()
        return {"external_id": instance_id}, service_address, service_port
    elif args.azure:
        log('Getting Azure instance ID')
        instance_id = get_azure_instance_id()
        service_address = get_azure_service_address()
        return {"external_id": instance_id}, service_address, service_port
    else:
        if args.show_config:
            show_config(api_client)
            sys.exit(0)
        else:
            log('Define at least --standalone or a cloud provider')
            sys.exit(1)

def gather_standalone_parameters(args):
    def ips_from_ip_command():
        process = subprocess.Popen(['/sbin/ip', 'addr'],
                                   stdout=subprocess.PIPE)
        out, err = process.communicate()
        if PY3:
            # to string
            out = out.decode()

        lines = out.split("\n")

        ips = []
        for line in lines:
            line = line.strip()

            if not line.startswith("inet ") and not line.startswith("inet6 "):
                continue

            elems = line.split(" ")
            ip = elems[1]
            ip = ip.split("/")[0]

            if (ip == "127.0.0.1" or ip == "::1" or ip == "" or
                    ip.startswith("fe80::")):
                continue

            ips.append(ip)

        return ips

    def get_system_uuid():
        try:
            with open('/etc/machine-id') as f:
                system_id = f.read()
                return system_id.strip()
        except Exception as e:
            log('    Reading /etc/machine-id failed: {}', str(e))
            log('    Fallback to dmidecode')

        process = subprocess.Popen(
            ['dmidecode', '--string', 'system-uuid'],
            stdout=subprocess.PIPE)
        out, err = process.communicate()
        if PY3:
            # to string
            out = out.decode()
        return out.strip()

    def get_name():
        process = subprocess.Popen(['hostname'], stdout=subprocess.PIPE)
        out, err = process.communicate()
        if PY3:
            # to string
            out = out.decode()
        return out.strip()

    def get_ssh_port():
        try:
            with open('/etc/ssh/sshd_config') as f:
                sshd_config_data = f.readlines()
                listen_address_line_seen = False
                for line in sshd_config_data:
                    line = line.strip()
                    if line.startswith("Port"):
                        # Port 222
                        tokens = line.split()
                        if len(tokens) >= 2 and tokens[1].isdigit():
                            return int(tokens[1])
                    elif line.startswith("ListenAddress"):
                        if listen_address_line_seen:
                            break
                        # ListenAddress 123.123.123.123:222
                        # ListenAddress 123.123.123.123
                        # ListenAddress host.name.net:222
                        # ListenAddress host.name.net
                        # ListenAddress [host.name.net]:222
                        # ListenAddress [host.name.net]
                        # ListenAddress [1234:f0d0:1002:11::2]:222
                        # ListenAddress [1234:f0d0:1002:11::2]
                        # ListenAddress 1234:f0d0:1002:11::2
                        tokens = line.split()
                        if len(tokens) >= 2:
                            parts = tokens[1].split(":")
                            if len(parts) == 2 and parts[1].isdigit():
                                return int(parts[1])
                            elif len(parts) > 2 and parts[len(parts)-2].endswith("]") and parts[len(parts)-1].isdigit():
                                return int(parts[len(parts)-1])
                            else:
                                # ListenAddress without port, continue scan
                                # until Port or another ListenAddress is seen.
                                listen_address_line_seen = True

        except Exception as e:
            log('    Reading /etc/ssh/sshd_config failed: {}', str(e))

        log('    Using default SSH port')
        return 22

    if args.openstack:
        log('Getting instance details from {}', AWS_API)
        addresses = get_openstack_instance_addresses()
        system_uuid = get_openstack_instance_id()
        name = get_aws_instance_name()
        service_address = get_openstack_service_address()
        cloud_provider = "OPENSTACK"
    elif args.aws:
        log('Getting instance details from {}', AWS_API)
        addresses = get_aws_instance_addresses()
        system_uuid = get_aws_instance_id()
        name = get_aws_instance_name()
        service_address = get_aws_service_address()
        cloud_provider = "AWS"
    elif args.google_cloud:
        log('Getting instance details from {}', AWS_API)
        addresses = get_google_cloud_instance_addresses()
        system_uuid = get_google_cloud_instance_id()
        name = get_google_cloud_instance_name()
        service_address = get_google_cloud_service_address()
        cloud_provider = "GOOGLECLOUD"
    elif args.azure:
        log('Getting instance details from {}', AZURE_API)
        addresses = get_azure_instance_addresses()
        system_uuid = get_azure_instance_id()
        name = get_azure_instance_name()
        service_address = get_azure_service_address()
        cloud_provider = "AZURE"
    else:
        log('Using locally available information')
        addresses = ips_from_ip_command()
        system_uuid = get_system_uuid()
        name = get_name()
        service_address = addresses[0]
        cloud_provider = ""

    service_port = get_ssh_port()

    # Remove the empty addresses from the list - instances may not have
    # public, private addresses all the time
    addresses = list(filter(None, addresses))

    log('    Instance ID:     {}', system_uuid)
    log('    Common name:     {}', name)
    log('    Addresses:       {}', ", ".join(addresses))
    log('    Cloud provider:  {}', cloud_provider)

    return {
        "addresses": addresses,
        "external_id": system_uuid,
        "common_name": name,
        "stand_alone_host": True,
    }, service_address, service_port


def write_ca_pub_key(key):
    with open("/etc/ssh/privx_ca.pub", 'w') as f:
        f.write(key + "\n")

def write_principals_command(command):
    principal_commands_file_name = "/etc/ssh/principals_command.sh"

    with open(principal_commands_file_name, 'w') as f:
        f.write(command + "\n")
        os.chmod(principal_commands_file_name, 0o755)


def write_principals(principals):
    if len(principals)>0:
        log("Configuring certificate login via shared accounts")
    auth_principals_dir = "/etc/ssh/auth_principals"

    if not os.path.exists(auth_principals_dir):
        os.makedirs(auth_principals_dir)
        os.chmod(auth_principals_dir, 0o755)

    for principal in principals:
        principal_name = encode_str(principal['principal'])
        filename = "{}/{}".format(auth_principals_dir, principal_name)

        lines = []
        disabled = False

        for role in principal['roles']:
            role_name = encode_str(role['name'])
            if role_name == "delegated-roles":
               role_name = "All PrivX roles"
               role["id"] = "delegated-roles"
            if role_name == "disabled":
               disabled = True
               break
            role_id = role['id']

            line = "{} # {}\n".format(role_id, role_name)
            lines.append(line)

        if disabled:
            lines = ["# Empty file. All roles disabled for the principal"]

        with open(filename, 'w') as f:
            f.write("".join(lines))
            os.chmod(filename, 0o644)



def create_user(user):
    subprocess.call(["adduser", "--system", "--no-create-home", user])


def check_user(user):
    try:
        pwd.getpwnam(user)
    except Exception:
        raise Exception("User " + user + " does not exist")


def write_personal_account_roles(personal_account_roles):

    if len(personal_account_roles)>0:
        log("Configuring certificate login via personal directory accounts")
    personal_account_roles_filename = "/etc/ssh/personal_account_roles"

    lines = []

    for role in personal_account_roles:
        role_id = role['id']
        role_name = encode_str(role['name'])
        if role_name == "delegated-roles":
           role_name = "All PrivX roles"
        line = "{} # {}\n".format(role_id, role_name)
        lines.append(line)

    with open(personal_account_roles_filename, 'w') as f:
        f.write("".join(lines))
        os.chmod(personal_account_roles_filename, 0o644)


SSHD_CONFIG_FILE_PATH = "/etc/ssh/sshd_config"


def modify_sshd_conf(authorized_principals_command_user):
    lines_to_add = [
        "TrustedUserCAKeys /etc/ssh/privx_ca.pub\n",
        "AuthorizedPrincipalsCommand /etc/ssh/principals_command.sh %u\n",
        "AuthorizedPrincipalsCommandUser \""
        + authorized_principals_command_user + "\"\n",
    ]

    with open(SSHD_CONFIG_FILE_PATH, 'r') as f:
        lines = f.readlines()

    delete_lines = []
    for i, line in enumerate(lines):
        if (line.startswith("TrustedUserCAKeys") or
                line.startswith("AuthorizedPrincipalsCommand") or
                line.startswith("AuthorizedPrincipalsFile") or
                line.startswith("AuthorizedPrincipalsCommandUser")):
            delete_lines.append(i)

    for i, line in enumerate(delete_lines):
        del lines[line - i]

    # Insert PrivX config lines after first comments (if any).
    insert_index = 0
    for i, line in enumerate(lines):
        if (not line.startswith("# ") and
                line != "#\n" and
                line != "\n"):
            insert_index = i + 1
            break

    # Insert the Privx config lines.
    lines.insert(insert_index - 1, "\n")
    for i, line in enumerate(lines_to_add):
        lines.insert(insert_index + i, line)
    lines.insert(insert_index + len(lines_to_add), "\n")

    # Remove double empty lines after the changes.
    delete_lines = []
    for i, line in enumerate(lines):
        if (i > 0) and (lines[i - 1] == "\n") and (line == "\n"):
            delete_lines.append(i)
    for i, line in enumerate(delete_lines):
        del lines[line - i]

    with open(SSHD_CONFIG_FILE_PATH, 'w') as f:
        for line in lines:
            f.write("{}".format(line))


def get_ssh_host_public_keys():
    path = '/etc/ssh/'
    keytypes = ['rsa', 'dsa', 'ecdsa', 'ed25519']
    filenames = ["{}ssh_host_{}_key.pub".format(path, t) for t in keytypes]
    existing_files = [filename for filename in filenames
                      if os.path.isfile(filename)]

    keys = []
    for filename in existing_files:
        with (open(filename)) as f:
            key = f.read()
            key = key.strip()
            keys.append(key)

    return keys

def os_is_supported():
    supported_os = ['rocky', 'centos', 'rhel', 'fedora', 'debian', 'ubuntu']
    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release') as f:
            contents = f.read()
            contents = contents.lower()
            if any([
                True if os_name in contents else False
                for os_name in supported_os
            ]):
                return True

    filenames = [
        '/etc/redhat-release',
        '/etc/rocky-release', 
        '/etc/fedora-release',
        '/etc/centos-release',
    ]

    for filename in filenames:
        if os.path.exists(filename):
            return True

    return False

def reload_sshd():
    log('    Trying to reload ssh service')
    retval = subprocess.call(['service', 'ssh', 'reload'])
    if retval != 0:
        log('    Failed, retrying with sshd service instead')
        retval = subprocess.call(['service', 'sshd', 'reload'])

    if retval != 0:
        raise Exception("Failed to reload sshd configuration")

    log('    Success')


class ApiClient(object):
    def __init__(self, hostname, ca_cert, oauth_client_id, oauth_client_secret,
                 api_client_id, api_client_secret, access_group_id):
        self.hostname = hostname
        self.ca_cert = ca_cert
        self.oauth_client_id = oauth_client_id
        self.oauth_client_secret = oauth_client_secret
        self.api_client_id = api_client_id
        self.api_client_secret = api_client_secret
        self.api_access_group_id = access_group_id
        self.token = None

        # In Python 2, PEM certs must be encoded to work properly.
        if ('-----BEGIN CERTIFICATE-----' in self.ca_cert and
                sys.version_info.major < 3):
            self.ca_cert = unicode(self.ca_cert)

    def _get_connection(self):
        ssl_context = ssl.create_default_context(cadata=self.ca_cert)
        ssl_context.load_default_certs()
        return httplib.HTTPSConnection(self.hostname, context=ssl_context)

    def _base64encode(self, val):
        if PY3:
            val = val.encode()

        encoded = base64.b64encode(val)

        if PY3:
            # a string return is expected, decode back to string.
            return encoded.decode()

        return encoded

    def authenticate(self):
        conn = self._get_connection()
        params = urlencode({
            'grant_type': 'password',
            'username': self.api_client_id,
            'password': self.api_client_secret,
        })

        basic_auth = self._base64encode(
            "{}:{}".format(self.oauth_client_id, self.oauth_client_secret))

        headers = {
            "Content-type": "application/x-www-form-urlencoded",
            "Authorization": "Basic {}".format(basic_auth),
        }

        conn.request("POST", "/auth/api/v1/oauth/token", params, headers)
        resp = conn.getresponse()
        body = resp.read()

        if resp.status != 200:
            conn.close()
            raise Exception(
                "Failed to authenticate: HTTP {}\n{}".format(resp.status, body))

        if PY3:
            body = body.decode()
        resp_msg = json.loads(body)
        self.token = resp_msg['access_token']

        conn.close()

    def call(self, method, endpoint, msg):
        conn = self._get_connection()
        headers = {
            "Content-type": "application/json",
            "Authorization": "Bearer {}".format(self.token),
        }

        conn.request(method, endpoint, json.dumps(msg), headers)
        resp = conn.getresponse()
        body = resp.read()

        conn.close()

        if PY3:
            body = body.decode()

        return resp.status, body

    def get_ca_public_key(self):
        filters = urlencode({
            'access_group_id': self.api_access_group_id,
        })
        status, resp = self.call("GET", "/authorizer/api/v1/cas?" + filters, {})
        if status != 200:
            raise Exception(
                "Failed to get CA public key: HTTP {}".format(status))

        ca_public_key = json.loads(resp)[0]['public_key_string']
        return ca_public_key

    def get_principals_command(self):
        status, principals_command = self.call("GET",
            "/authorizer/api/v1/deploy/principals_command.sh", {})
        if status != 200:
            raise Exception(
                "Failed to get principals_command.sh: HTTP {}".format(status))

        return principals_command

    def _resolve_role_ids(self, role_names):
        if role_names:
          status, resp = self.call("POST", "/role-store/api/v1/roles/resolve",
                                 role_names)
          if status != 200:
              raise Exception(
                  "Failed to resolve role IDs: HTTP {}".format(status))

          roles = json.loads(resp)['items']
        else:
          roles = []

        role_ids = {}
        # generate lookup table
        for role in roles:
            role_ids[role['name']] = role['id']
        role_ids['delegated-roles'] = 'delegated-roles'
        role_ids['disabled'] = 'disabled'

        return role_ids

    def resolve_principal_role_ids(self, principals):
        role_names = []
        for princ in principals:
            for role in princ['roles']:
                if role['name'] != 'delegated-roles' and role['name'] != 'disabled':
                    role_names.append(role['name'])

        # send only unique names
        role_names = list(set(role_names))
        role_ids = {}
        if role_names:
            role_ids = self._resolve_role_ids(role_names)

        for princ in principals:
            resolved_roles = []
            for role in princ['roles']:
                if role['name'] == 'delegated-roles' or role['name'] == 'disabled':
                    role['id'] = role['name']
                    resolved_roles.append(role)
                else:
                    if not role_ids.get(role['name']):
                        raise Exception(
                            "Failed to resolve role ID for role '{}'".format(
                                encode_str(role['name'])))
                    role['id'] = role_ids[role['name']]
                    resolved_roles.append(role)
            princ['roles'] = resolved_roles

        return principals

    def resolve_personal_account_role_ids(self, roles):
        role_names = []
        for role in roles:
            if role['name'] != 'delegated-roles':
                role_names.append(role['name'])

        # send only unique names
        role_names = list(set(role_names))
        if role_names:
            role_ids = self._resolve_role_ids(role_names)
            for role in roles:
                name = role['name']
                if role['name'] != 'delegated-roles':
                    if not role_ids.get(name):
                        raise Exception(
                            "Failed to resolve role ID for role '{}'".format(
                                encode_str(name)))

                role['id'] = role_ids[name]

        return roles


    def parse_principals_from_files(self, user_defined_account_roles):
        auth_principals_dir = "/etc/ssh/auth_principals"
        personal_account_roles_file = "/etc/ssh/personal_account_roles"

        principals = []
        if os.path.exists(auth_principals_dir): # principals
            for filename in os.listdir(auth_principals_dir):
                princ = []
                stat = []
                role = {'roles': [], 'principal': filename}
                for line in open(auth_principals_dir+"/"+filename,'r'):
                    l = line.rstrip()
                    val = extract_rolename(l)
                    if val[0] == '' or val[1] == '':
                        continue
                    if val[1] != 'delegated-roles': # Let's not send delegated-roles to server.
                        role['roles'].append({'name': val[0], 'id': val[1]})
                principals.append(role)

        if os.path.exists(personal_account_roles_file): # personal-account-roles
            role = {'use_user_account': True, 'roles': []}
            for line in open(personal_account_roles_file,'r'):
                l = line.rstrip()
                val = extract_rolename(l)
                if val[0] == '' or val[1] == '':
                       continue
                if val[1] != 'delegated-roles': # Let's not send delegated-roles to server.
                    role['roles'].append({'name': val[0], 'id': val[1]})
            principals.append(role)

        if len(user_defined_account_roles)>0:
	        principals.append({
                'roles': user_defined_account_roles,
            })

        return principals


    def register_host(self, principals, host_keys, service_address, service_port, user_defined_account_roles,
                      enable_auditing=False, trust_on_first_use=False,sshd_version="", **args):

        # Send also old config to the server, not just the principals and roles defined in command line:
        principals = self.parse_principals_from_files(user_defined_account_roles)

        args['ssh_host_public_keys'] = [{"key": key} for key in host_keys]
        args['principals'] = principals
        args['services'] = [
            {"service": "SSH", "address": service_address, "port": service_port}
        ]
        args['audit_enabled'] = enable_auditing
        args["tofu"] = trust_on_first_use
        args['access_group_id'] = self.api_access_group_id

        args["sshd_version"] = sshd_version

        status, response = self.call(
            "POST", "/host-store/api/v1/hosts/deploy", args)

        if status != 200:
            raise Exception("Failed to register host to PrivX: HTTP {}: {}".format(status, json.loads(response)['error_message']))


parser = argparse.ArgumentParser(description='deploy.py version '+DEPLOY_PY_VERSION+'. Configures sshd for certificate authentication and registers host with PrivX.')
parser.add_argument('--api-client-id', help='PrivX API client id')
parser.add_argument('--api-client-secret', help='PrivX API client secret')
parser.add_argument('--oauth-client-id', help='PrivX API OAUTH client id')
parser.add_argument('--oauth-client-secret',
    help='PrivX API OAUTH client secret')
parser.add_argument('--api-hostname', help='PrivX API hostname')
parser.add_argument('--api-ca-cert-file',
    help='PrivX API TLS CA certificate file name')
parser.add_argument('--standalone', action='store_true',
    help='This server will not be added by a scan script. IP is gathered locally')
parser.add_argument('--common-name',
    help='If specified, defines the instance name. For cloud hosts, if host scanning and tag import is enabled, this value will be overwritten with server\'s Name tag.')
parser.add_argument('--openstack', action='store_true',
    help='Instance is running in Openstack')
parser.add_argument('--aws', action='store_true',
    help='Instance is running in Amazon Web Services')
parser.add_argument('--google-cloud', action='store_true',
    help='Instance is running in Google Cloud')
parser.add_argument('--azure', action='store_true',
    help='Instance is running in Microsoft Azure')
parser.add_argument('--run-anyway', action='store_true',
    help='Run even though this OS is not supported')
parser.add_argument('--principals',
    help='Allow PrivX to access this host using given principal-roles combinations. Principals and their roles encoded as principal1=role_name1,role_name2:principal2=role_name3')
parser.add_argument('--delegated-principals',
    help='Allow PrivX to access this host with any role for the listed principals. Principals are encoded as principal1,principal2')
parser.add_argument('--personal-account-roles',
    help='Configure Directory account type. Roles that grant personal account access with user''s unix_username, encoded as role_name1,role_name2')
parser.add_argument('--delegated-personal-account-roles', action='store_true',
    help='Configure this host to approve all valid certificate requests from PrivX for Directory account logins, even if role UUID is not configured to /etc/ssh/personal_account_roles. This feature makes possible to access hosts via new roles in PrivX without making any configuration changes on target hosts.')
parser.add_argument('--user-defined-account-roles',
    help='Roles that grant user-defined account access, encoded as role_name1,role_name2. This is a PrivX configuration option, this option does not enable certificate-based authentication for the specified roles.')
parser.add_argument('--authorized-principals-command-user',
    help='Username for sshd_config AuthorizedPrincipalsCommandUser, user is created if it does not exists')
parser.add_argument('--rotate-ca', action='store_true',
    help='Only install CA public key from PrivX and exit')
parser.add_argument('--enable-auditing', action='store_true',
    help='Enable auditing for the host')
parser.add_argument('--trust-on-first-use', action='store_true',
    help='Enable Trust on first use, host certificate can be accepted without admin approving it first.')
parser.add_argument('--configure-only', action='store_true',
    help='Reconfigure sshd and role config, but do not register host to PrivX.')
parser.add_argument('--show-config', action='store_true',
    help='Show which PrivX roles and principals SSHD allows to connect to the host.')
parser.add_argument('--clean', action='store_true',
    help='Remove all principal files before running the certificate config.')
parser.add_argument('--service-address',
    help='Service Address will be used to connect the host from PrivX.')

def decode_str(val):
    if PY3:
        return val
    return val.decode(py2_encoding)


def encode_str(val):
    if PY3:
        return val
    return val.encode(py2_encoding)


def parse_principals(principals_str, delegated_principals_str):
    principals = []
    delegated = {}

    if delegated_principals_str:
        tmp = delegated_principals_str.split(",")
        for t in tmp:
            if principals_str != "":
                principals_str = principals_str+":"
            principals_str = principals_str+t+"=delegated-roles"

    if principals_str != "":
        principals_str = principals_str[:-1] if principals_str[-1] == ':' else principals_str

        for principal_str in principals_str.split(':'):
            components = principal_str.split('=')

            if len(components) != 2:
                raise ValueError('Invalid principal definition: {}'.format(principal_str))

            principal = components[0]
            try:
                pwd.getpwnam(principal)
            except KeyError:
                log('Warning: User "'+principal+'" does not exist.')

            roles = components[1].split(',')

            exists = 0
            for p in principals:
                if p['principal'] == decode_str(principal):
                    p['roles'] = p['roles'] + [{'name': decode_str(role)} for role in roles]
                    exists = 1
                    break

            if not exists:
                principals.append({
                    'principal': decode_str(principal),
                    'roles': [{'name': decode_str(role)} for role in roles],
             })

    return principals


def parse_personal_account_roles(roles_str):
    roles = []
    if roles_str:
        for role in roles_str.split(','):
            roles.append({'name': decode_str(role)})
    return roles


def rotate_ca(api_client):
    log('GET ssh user CA public key from PrivX')
    try:
        ca_public_key = api_client.get_ca_public_key()
    except Exception as err:
        log('Failed to GET ssh user CA public key: {}', err)
        sys.exit(1)

    log('Write CA public')
    write_ca_pub_key(ca_public_key)

    log('Reload sshd configuration')
    reload_sshd()

def check_sshd_config():
    cas = "None. No certificates configured for this host.\n"
    try:
        output = subprocess.Popen(['sshd','-T'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        stdout,stderr = output.communicate()
    except:
        output = subprocess.Popen(['ssh','-T'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
        stdout,stderr = output.communicate()
    for line in stdout.decode("utf-8").split('\n'):
        if line.startswith("usepam"):
            print(line)
        if line.startswith("trustedusercakeys"):
            if not line == "trustedusercakeys /etc/ssh/privx_ca.pub":
                print("Warning: CA certificate path changed!")
            print(line)
            privx_ca = line.split()[1]
            if not os.path.exists(privx_ca):
                print("File "+privx_ca+" not found!")
            else:
                file = open('/etc/ssh/privx_ca.pub', mode='r')
                cas = file.read()
                file.close()
        if line.startswith("authorizedprincipalscommand "):
            if not line == "authorizedprincipalscommand /etc/ssh/principals_command.sh %u":
                print("Warning: AuthorizedPrincipalsCommand path changed!")
            print(line)
        if line.startswith("authorizedprincipalscommanduser"):
            print(line)
        if line.startswith("permitrootlogin"):
            print(line)
    print("\nAccepted CA certificates:")
    print(cas)

def extract_rolename(str):
    names = str.split("#")
    if len(names) < 2:
       return "",""
    role = names[1].strip()
    uuid = names[0].strip()
    if role == "delegated-roles" or role == "disabled":
       return "",""
    return role,uuid

def show_config(api_client):
    print("PrivX deploy script version "+DEPLOY_PY_VERSION)
    print("Access group ID "+API_ACCESS_GROUP_ID+"\n")

    check_sshd_config()

    auth_principals_dir = "/etc/ssh/auth_principals"
    personal_account_roles_file = "/etc/ssh/personal_account_roles"

    if not os.path.exists("/etc/ssh/principals_command.sh"):
        print("/etc/ssh/principals_command.sh is missing!")
        exit(1)

    principals = []
    if os.path.exists(auth_principals_dir):
        for filename in os.listdir(auth_principals_dir):
            print("\nCertificate login with principal '"+filename+"' allowed for these roles:")
            princ = []
            stat = []
            role_names = []
            for line in open(auth_principals_dir+"/"+filename,'r'):
                l = line.rstrip()
                princ += ["    "+l[:60]+(l[60:] and '..')]
                val = extract_rolename(l)
                if val[0] != "" and val[1] != "" and val[1] != "delegated-roles":
                    try:
                      role_ids = api_client._resolve_role_ids([val[0]])
                      if len(role_ids)>0:
                        if val[1] == role_ids[val[0]]:
                           stat += ['OK - verified by '+API_HOSTNAME]
                        else:
                           stat += ['Role id does not match the name - '+API_HOSTNAME]
                    except Exception as err:
                      stat += ['Failed to verify - '+API_HOSTNAME]
                else:
                    stat += ['']
            for i, t in zip(princ, stat):
                print(i.ljust(66)+ "     "+t)
            principals += [filename]

    if os.path.exists(personal_account_roles_file):
        print("\nCertificate login with any principal except '"+','.join(principals)+"' when using Directory account type, allowed for these roles:")
        for line in open(personal_account_roles_file,'r'):
                print("    "+line.rstrip())
    else:
        if len(principals) == 0:
            print("Host has not been configured to allow any PrivX roles via certificate login.")
            print("Use --principals, --personal-account-roles, --delegated-principals or --delegated-personal-account-roles flags to do that.")

def is_valid_python_version():
    try:
        temp_context = ssl.create_default_context()
        httplib.HTTPSConnection("test", context=temp_context)
    except (TypeError, AttributeError):
        # Catch only expected error types.
        return False

    return True

def resolve_sshd_version(service_port):

    print("Connecting to 127.0.0.1 port {}".format(service_port))

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', service_port))
        sshd_version = s.recv(1024).decode("utf-8")
        s.close()
    except Exception as e:
        print("Warning: Failed to connect, could not resolve server version!")
        print(e)
        return

    # https://tools.ietf.org/html/rfc4253#section-4.2
    log("SSHD version: "+sshd_version.rstrip())
    tmp = sshd_version.split('-')
    if len(tmp)<3:
        print("Invalid version string")
        sys.exit(1)
    if tmp[0] != "SSH":
        print("Invalid version string. SSH expected.")
        sys.exit(1)
    if not tmp[2].startswith("OpenSSH"):
        print("OpenSSH server not found. This script is compatible with OpenSSH server for certificate configuration.")
        sys.exit(1)
    if tmp[1] != "2.0":
        print("Invalid SSH protocol version: "+tmp[1])
        sys.exit(1)
    temp = tmp[2].split(" ")[0] # strip comments
    ver_string = temp.split("_")[1]

    log("OpenSSH version: "+ver_string.rstrip())
    # Version string can be 7, 7.4, 7.4p2, 7.4.1 ...
    leading_float = re.match(r"(\d+(\.\d*)?)", ver_string).group(0)
    ver = float(leading_float)
    if ver < 5.6:
        print("Deprecated OpenSSH version, 5.6 or greater expected. For login-as-self functionality, version 6.9 or greater is expected.")
        sys.exit(1)
    if ver < 6.9:
        print("Deprecated OpenSSH version. For login-as-self functionality, version 6.9 or greater is expected.")

    return sshd_version

def remove_principal_files():
    auth_principals_dir = "/etc/ssh/auth_principals"
    if os.path.exists(auth_principals_dir):
        for filename in os.listdir(auth_principals_dir):
            os.remove(auth_principals_dir+"/"+filename)
    if os.path.exists("/etc/ssh/personal_account_roles"):
        os.remove("/etc/ssh/personal_account_roles")
    print("\n** --clean flag defined, removed existing principal files. Certificate login via PrivX has now been blocked to this host.\n")

def main():
    if not is_valid_python_version():
        log('Unsupported Python version in use.')
        sys.exit(1)

    if os.geteuid() != 0:
        log('This scripts needs be run with root privileges')
        sys.exit(1)

    if len(sys.argv)==1:
      parser.print_help(sys.stderr)
      sys.exit(1)

    args = parser.parse_args()

    api_client_id = args.api_client_id or API_CLIENT_ID
    if not api_client_id:
        log('API client id not specified')
        sys.exit(1)

    api_client_secret = args.api_client_secret or API_CLIENT_SECRET
    if not api_client_secret:
        log('API client secret not specified')
        sys.exit(1)

    oauth_client_id = args.oauth_client_id or OAUTH_CLIENT_ID
    if not oauth_client_id:
        log('OAuth client id not specified')
        sys.exit(1)

    oauth_client_secret = args.oauth_client_secret or OAUTH_CLIENT_SECRET
    if not oauth_client_secret:
        log('OAuth client secret not specified')
        sys.exit(1)

    api_hostname = args.api_hostname or API_HOSTNAME
    if not api_hostname:
        log('API hostname not specified')
        sys.exit(1)

    ca_cert = API_CA_CRT
    if args.api_ca_cert_file:
        with open(args.api_ca_cert_file) as f:
            ca_cert = f.read()

    if not ca_cert:
        log('API Certificate trust anchor not specified')
        sys.exit(1)

    api_client = ApiClient(api_hostname, ca_cert, oauth_client_id,
                           oauth_client_secret, api_client_id,
                           api_client_secret, API_ACCESS_GROUP_ID)

    if args.rotate_ca:
        rotate_ca(api_client)
        sys.exit(0)

    if args.clean:
        remove_principal_files()

    if not args.configure_only and not args.show_config:
        if not args.standalone and not args.openstack and not args.aws and not args.google_cloud and not args.azure:
            if args.clean:
                sys.exit(0)

            log('Define at least --standalone or a cloud provider to register host to PrivX')
            sys.exit(1)

    if not args.principals and not args.delegated_principals and not args.personal_account_roles and not args.user_defined_account_roles and not args.delegated_personal_account_roles and not args.show_config:
        if args.clean:
            sys.exit(0)
        log('Define at least --principals or --delegated-principals or --personal-account-roles or --user-defined-account-roles or --delegated-personal-account-roles')
        sys.exit(1)

    principals = []
    try:
        pr = ""
        delegated_pr = ""
        if args.principals:
            pr = args.principals
        if args.delegated_principals:
            delegated_pr = args.delegated_principals
        principals = parse_principals(pr, delegated_pr)
    except ValueError as err:
        log('Failed to parse principals: {}', err)
        sys.exit(1)

    try:
        personal_account_roles = parse_personal_account_roles(args.personal_account_roles)
    except ValueError as err:
        log('Failed to parse personal account roles: {}', err)
        sys.exit(1)

    if not args.run_anyway and not os_is_supported():
        log('This operating system is not supported. To run this script anyway use --run-anyway.')
        sys.exit(1)

    try:
        api_client.authenticate()
    except Exception as err:
        log('Failed to authenticate with PrivX: {}', err)
        sys.exit(1)

    log('GET ssh user CA public key from PrivX')
    try:
        ca_public_key = api_client.get_ca_public_key()
    except Exception as err:
        log('Failed to GET ssh user CA public key: {}', err)
        sys.exit(1)

    log('GET principals_command.sh from PrivX')
    try:
        principals_command = api_client.get_principals_command()
    except Exception as err:
        log('Failed to GET principals_command.sh: {}', err)
        sys.exit(1)

    log('Resolve role IDs')
    try:
        principals = api_client.resolve_principal_role_ids(principals)
    except Exception as err:
        log('{}', err)
        sys.exit(1)

    try:
        personal_account_roles = api_client.resolve_personal_account_role_ids(personal_account_roles)
    except Exception as err:
        log('{}', err)
        sys.exit(1)

    try:
        if args.delegated_personal_account_roles:
            personal_account_roles.append({'name': "All PrivX roles", 'id': "delegated-roles"})
    except ValueError as err:
        log('Failed to append delegated-roles: {}', err)
        sys.exit(1)

    try:
        user_defined_account_roles = []
        if args.user_defined_account_roles:
            user_defined_account_roles = parse_personal_account_roles(args.personal_account_roles)
            user_defined_account_roles = api_client.resolve_personal_account_role_ids(user_defined_account_roles)
    except Exception as err:
        log('{}', err)
        sys.exit(1)

    log('Read ssh public host keys')
    keys = get_ssh_host_public_keys()

    if not args.standalone:
        parameters, service_address, service_port = gather_parameters(args, api_client)
    else:
        log('Standalone mode')
        parameters, service_address, service_port = gather_standalone_parameters(args)
    if args.common_name:
        parameters['common_name'] = args.common_name

    sshd_version = resolve_sshd_version(service_port)

    authorized_principals_command_user = "nobody"
    try:
        if args.authorized_principals_command_user:
            user = decode_str(args.authorized_principals_command_user)
            log('Creating user "' + user + '"')
            create_user(user)
            authorized_principals_command_user = user

        log('Checking user "' + authorized_principals_command_user + '" exists')
        check_user(authorized_principals_command_user)
    except Exception as err:
        log('{}', err)
        sys.exit(1)

    log('Modifying sshd config')
    modify_sshd_conf(authorized_principals_command_user)

    log('Write CA public key and principals')
    write_ca_pub_key(ca_public_key)
    write_principals_command(principals_command)
    write_principals(principals)
    if personal_account_roles:
        write_personal_account_roles(personal_account_roles)
        principals.append({
            'use_user_account': True,
            'roles': personal_account_roles,
        })
    if args.user_defined_account_roles:
        principals.append({
            'roles': user_defined_account_roles,
        })

    log('Reload sshd configuration')
    reload_sshd()

    if args.service_address:
        service_address = args.service_address

    if not args.configure_only:
        log('Registering host to access group "'+API_ACCESS_GROUP_ID+'" with instance_id, roles and hostkeys')
        try:
            api_client.register_host(
                principals, keys, service_address, service_port, user_defined_account_roles,
                args.enable_auditing, args.trust_on_first_use, sshd_version, **parameters)
        except Exception as e:
            log("Error: {}", str(e))
            sys.exit(1)
    else:
        log("--configure-only flag used, not notifying PrivX about the changes.")

    if args.show_config:
        show_config(api_client)

if __name__ == "__main__":
    main()
