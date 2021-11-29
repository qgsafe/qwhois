# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import division

import re
import sys
import os
import subprocess
import socket
from future import standard_library
from builtins import *
from netaddr.ip import *
from .parser import WhoisEntry
from .whois import NICClient

standard_library.install_aliases()
suffixes = None


def whois(url, command=False, flags=0, timeout=10):
    # 获取域名
    print("url: ", url)
    if is_ip(url):
        result = socket.gethostbyaddr(url)
        url = result[0]
    domain = extract_domain(url)
    print("domain: ", domain)

    if command:
        # try native whois command
        r = subprocess.Popen(['whois', domain], stdout=subprocess.PIPE)
        text = r.stdout.read().decode()
    else:
        # try builtin client
        nic_client = NICClient()
        text = nic_client.whois_lookup(domain, flags, timeout)
    # open("whois/" + domain, 'w').write(text)
    # print(text)

    return text


def extract_domain(url):
    """Extract the domain from the given URL

    >>> print(extract_domain('http://www.google.com.au/tos.html'))
    google.com.au
    >>> print(extract_domain('abc.def.com'))
    def.com
    >>> print(extract_domain(u'www.公司.hk'))
    公司.hk
    >>> print(extract_domain('chambagri.fr'))
    chambagri.fr
    >>> print(extract_domain('www.webscraping.com'))
    webscraping.com
    >>> print(extract_domain('198.252.206.140'))
    stackoverflow.com
    >>> print(extract_domain('102.112.2O7.net'))
    2o7.net
    >>> print(extract_domain('globoesporte.globo.com'))
    globo.com
    >>> print(extract_domain('1-0-1-1-1-0-1-1-1-1-1-1-1-.0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0-0-0-0.info'))
    0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0-0-0-0.info
    >>> print(extract_domain('2607:f8b0:4006:802::200e'))
    1e100.net
    >>> print(extract_domain('172.217.3.110'))
    1e100.net
    """

    # load known TLD suffixes
    global suffixes
    if not suffixes:
        # downloaded from https://publicsuffix.org/list/public_suffix_list.dat
        tlds_path = os.path.join(os.getcwd(), os.path.dirname(__file__), 'data', 'public_suffix_list.dat')
        with open(tlds_path, encoding='utf-8') as tlds_fp:
            suffixes = set(
                line.encode('utf-8') for line in tlds_fp.read().splitlines() if line and not line.startswith('//')
            )

    if not isinstance(url, str):
        url = url.decode('utf-8')
    url = re.sub('^.*://', '', url)
    url = url.split('/')[0].lower()

    # find the longest suffix match
    url = to_utf8(url)
    domain = b''
    for section in reversed(url.split('.')):
        if domain:
            domain = b'.' + domain
        domain = section.encode('utf-8') + domain

        if domain not in suffixes:
            break
    # print("extract_domain: ", domain.decode('utf-8'))

    return to_punycode(domain.decode('utf-8'))


# 域名编码
def to_punycode(url):
    domain = b''
    for section in reversed(url.split('.')):
        if domain:
            domain = b'.' + domain

        if not is_ascii(section):
            section = b'xn--' + section.encode('punycode')
        else:
            section = section.encode('utf-8')
        domain = section + domain

    return domain.decode('utf-8')


# punycode编码转回utf8
def to_utf8(url):
    domain = b''
    for section in reversed(url.split('.')):
        if domain:
            domain = b'.' + domain

        if section.find('xn--') == 0:
            section = section.replace('xn--', '').encode('utf-8').decode('punycode').encode('utf-8')
        else:
            section = section.encode('utf-8')
        domain = section + domain

    return domain.decode('utf-8')


# 判断ip
def is_ip(url):
    try:
        IPAddress(url)
        return True
    except:
        return False


# 判断是否全是ASCII码
def is_ascii(value):
    for c in value:
        if ord(c) > 0x7f:
            return False
    return True


if __name__ == '__main__':
    try:
        url = sys.argv[1]
    except IndexError:
        print('Usage: %s url' % sys.argv[0])
    else:
        print(whois(url, timeout=30))
