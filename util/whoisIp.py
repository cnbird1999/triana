#-------------------------------------------------------------------------------
# Name:        WhoisIP
# Purpose:     GET Whois Records. Return an JSON object
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------

import Queue
import threading
import urllib2
import time
import socket
import urllib
socket.setdefaulttimeout(15)
import urlparse
import os
from common.constants import COLLECTOR_ROOT
import logging
from common.config import ConfigFile
from common.opener import DownloadUrl
import json
import tldextract

log = logging.getLogger(__name__)

queue = Queue.Queue()
results = Queue.Queue()

class WhoisIP(threading.Thread):
    """Threaded Url Grab"""
    def __init__(self, queue):
        super(WhoisIP,self).__init__()
        self.queue = queue
        self.stopRequest = threading.Event()
        self.whois = dict()

    def run(self):
        while not self.stopRequest.isSet():
            try:
                #grabs host from queue
                url,domain = self.queue.get(True,0.05)
                self.download(url,domain)
                results.put(self.whois)
            except Queue.Empty:
                continue

    def join(self,timeout=None):
        self.stopRequest.set()
        super(WhoisIP,self).join(timeout)

    def download(self,url,domain):
        try:
            #DownloadUrl().retrieve(host,os.path.join(COLLECTOR_ROOT,"ip",output+".txt"))
            d = urllib.urlopen(url.format(domain))
            datos = d.read()
            ustr_to_load = unicode(datos, 'latin-1')
            jason = json.loads(ustr_to_load)
            self.whois[domain] = jason
            log.info("Downloaded Whois information for domain %s" %domain)
        except Exception:
            log.error("Unable to download Whois information for domain %s" %domain)
            pass


def doWhoIp(ipaddress):
    whois = dict()
    #spawn a pool of threads, and pass them queue instance
    query = Queue.Queue()
    pool = [WhoisIP(queue = query)for i in range(20)]

    #Start all threads
    for thread in pool:
        thread.start()

    #populate queue with data
    parser = ConfigFile()
    url = parser.get("Whois","ipaddress")
    for ip in ipaddress:
        if ip is not None:
            #hostname = tldextract.extract(domain)
            #d = hostname.domain+"."+hostname.tld
            query.put((url,ip))
            whois.update(results.get())


    for thread in pool:
        thread.join()

    return whois








"""domains = list()
#domains.append("123.123.123.123")
#domains.append("80.58.0.33")
domains.append("8.8.8.8")
whois = doWhois(domains)
for ip,data in whois.iteritems():
    print data["RegistryData"]["AbuseContact"]"""



"""def main():
    #d = urllib.urlopen("http://whoiz.herokuapp.com/lookup.json?url=tube8.com")
    d = urllib.urlopen("http://adam.kahtava.com/services/whois.json?query=123.123.123.123")
    #e = urllib.urlopen("http://adam.kahtava.com/services/whois.json?query=923.123.123.223")
    datos = d.read()
    jason = json.loads(datos)
    error = jason.get("Errors")
    if not error:
        domainname =  jason.get("DomainName")
        registrydata = jason.get("RegistryData")
        print registrydata["AbuseContact"]["Phone"]
    pass

if __name__ == '__main__':
    main()"""

