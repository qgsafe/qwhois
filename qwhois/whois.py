# -*- coding: utf-8 -*-

"""
Whois client for python

transliteration of:
http://www.opensource.apple.com/source/adv_cmds/adv_cmds-138.1/whois/whois.c

Copyright (c) 2010 Chris Wolf

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import

import json
import os
import re
import socket


class NICClient(object):

    # 特殊服务器地址
    ANICHOST = "whois.arin.net"
    LNICHOST = "whois.lacnic.net"
    RNICHOST = "whois.ripe.net"
    PNICHOST = "whois.apnic.net"
    QNICHOST_TAIL = ".whois-servers.net"
    BNICHOST = "whois.registro.br"
    NORIDHOST = "whois.norid.no"
    PANDIHOST = "whois.pandi.or.id"
    DENICHOST = "de.whois-servers.net"
    HR_HOST = "whois.dns.hr"
    DK_HOST = "whois.dk-hostmaster.dk"
    WHOIS_SERVER_MAP = None
    # whois服务默认端口43
    WHOIS_SERVER_PORT = 43

    # CA_HOST = "whois.ca.fury.ca"
    # PE_HOST = "kero.yachay.pe"
    WHOIS_RECURSE = 0x01
    WHOIS_QUICK = 0x02

    ip_whois = [LNICHOST, RNICHOST, PNICHOST, BNICHOST, PANDIHOST]

    @staticmethod
    def find_whois_server(buf, hostname, query):
        """Search the initial TLD lookup results for the regional-specifc
        whois server for getting contact details.
        """
        host = None
        match = re.compile('Domain Name: {}\s*.*?Whois Server: (.*?)\s'.format(query), flags=re.IGNORECASE | re.DOTALL).search(buf)
        if match:
            host = match.groups()[0]
            # if the whois address is domain.tld/something then
            # s.connect((hostname, 43)) does not work
            if host.count('/') > 0:
                host = None
        elif hostname == NICClient.ANICHOST:
            for nic_host in NICClient.ip_whois:
                if buf.find(nic_host) != -1:
                    host = nic_host
                    break
        return host

    @staticmethod
    def choose_server(domain):
        # load whois server map
        if not NICClient.WHOIS_SERVER_MAP:
            server_path = os.path.join(os.getcwd(), os.path.dirname(__file__), 'data', 'whois_server.map')
            with open(server_path, encoding='utf-8') as tlds_fp:
                NICClient.WHOIS_SERVER_MAP = json.loads(tlds_fp.read())

        if domain.endswith("-NORID"):
            return NICClient.NORIDHOST
        if domain.endswith("id"):
            return NICClient.PANDIHOST
        if domain.endswith("hr"):
            return NICClient.HR_HOST

        domain = domain.split('.')
        if len(domain) < 2:
            return None
        tld = domain[-1]
        if tld[0].isdigit():
            return NICClient.ANICHOST
        elif tld in NICClient.WHOIS_SERVER_MAP:
            return NICClient.split_host(NICClient.WHOIS_SERVER_MAP[tld])
        else:
            return tld + NICClient.QNICHOST_TAIL

    @staticmethod
    def split_host(host):
        hosts = host.split(':')
        if len(hosts) >= 2:
            NICClient.WHOIS_SERVER_PORT = hosts[-1]
            return hosts[-2]
        else:
            return host

    def whois(self, domain, hostname, flags, many_results=False, port=43, timeout=10):
        response = b''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((hostname, port))
            if hostname == NICClient.DENICHOST:
                domain_bytes = "-T dn,ace -C UTF-8 " + domain
            elif hostname == NICClient.DK_HOST:
                domain_bytes = " --show-handles " + domain
            elif hostname.endswith(NICClient.QNICHOST_TAIL) and many_results:
                domain_bytes = '=' + domain
            else:
                domain_bytes = domain
            s.send(bytes(domain_bytes, 'utf-8') + b"\r\n")

            # recv returns bytes
            while True:
                d = s.recv(4096)
                response += d
                if not d:
                    break
            s.close()

            host = None
            response = response.decode('utf-8', 'replace')
            if 'with "=xxx"' in response:
                return self.whois(domain, hostname, flags, True, port=port, timeout=timeout)
            if flags & NICClient.WHOIS_RECURSE and host is None:
                host = NICClient.find_whois_server(response, hostname, domain)
            if host is not None:
                response += self.whois(domain, host, 0, port=port, timeout=timeout)
        except socket.error as exc:
            response = "Error: trying to connect to socket: " + repr(exc)
            s.close()
        return response

    def whois_lookup(self, domain, flags, timeout):
        NICClient.WHOIS_SERVER_PORT = 43
        host = NICClient.choose_server(domain)
        if host is not None:
            result = self.whois(domain, host, flags, port=NICClient.WHOIS_SERVER_PORT, timeout=timeout)
        else:
            result = 'Error: Not find whois server'

        return result
