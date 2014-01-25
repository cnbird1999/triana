#-------------------------------------------------------------------------------
# Name:        Whois
# Purpose:     GET Whois Domains. Return an JSON Object
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

class Whois(threading.Thread):
    """Threaded Url Grab
    http://www.ibm.com/developerworks/aix/library/au-threadingpython/"""
    def __init__(self, queue):
        super(Whois,self).__init__()
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
        super(Whois,self).join(timeout)

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


def doWhois(domains):
    whois = dict()
    #spawn a pool of threads, and pass them queue instance
    query = Queue.Queue()
    pool = [Whois(queue = query)for i in range(20)]

    #Start all threads
    for thread in pool:
        thread.start()

    #populate queue with data
    parser = ConfigFile()
    url = parser.get("Whois","domain")
    for domain in domains:
        if domain is not None:
            hostname = tldextract.extract(domain)
            d = hostname.domain+"."+hostname.tld
            query.put((url,d))
            whois.update(results.get())


    for thread in pool:
        thread.join()

    return whois