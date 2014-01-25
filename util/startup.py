#-------------------------------------------------------------------------------
# Name:        STARTUP
# Purpose:     Main Script from TRIANA. Generate all operations
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
import os
import sys
from common.constants import COLLECTOR_ROOT
from util.utils import *
import logging
import codecs
from parse.reputation import *
from parse.DomainReputation import *
from lib.dnsmalware import DNSMalware
from lib.ip import doReputation
from lib.malware import doMalware
from util.whois import doWhois
from util.charts import Charts
from util.Info import *
from util.geo import *
from util.whoisIp import doWhoIp
from common.loader import *
from reporting.docxreport import make_word
from random import randint
import shutil
import re
from common.config import ConfigFile
from auth.malwarelu import MalwareLu

LEVELS = { 'debug':logging.DEBUG,
            'info':logging.INFO,
            'warning':logging.WARNING,
            'error':logging.ERROR,
            'critical':logging.CRITICAL,
            }

log = logging.getLogger()
pattern = r'[^\.z0-9]'
ipaddr = re.compile('(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}'
                +'(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))')

def Create_Structure(md5):
    """Create structure collector"""
    folders = ["charts",
               "domains",
               "ip",
               "malware",
               "log",
               "reports",
               "tmp",
               "download",
               "tmpannex"]
    reportdir = md5+"_"+str(randint(2,1000))
    report = ["Report","Download","JSON","Annex"]
    try:
        create_folders(root=COLLECTOR_ROOT,folders=folders)
        create_folders(root=os.path.join(COLLECTOR_ROOT,"reports",reportdir),folders=report)
        return reportdir
    except:
        log.error("An error ocurred creating folders structure...")
        sys.exit()


def init_logging(level_name):
    """Initialize logging."""
    level = LEVELS.get(level_name, logging.NOTSET)
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    log.addHandler(sh)
    fh = logging.FileHandler(os.path.join(COLLECTOR_ROOT, "log", "collector.log"))
    fh.setFormatter(formatter)
    log.addHandler(fh)
    log.setLevel(level)

def Triana(md5hash,options,reportdir):
    dns = dict()
    checkDNS = DNSMalware(md5hash)
    dns["owasp"] = checkDNS.CheckMalwareOwasp()
    dns["mhr"] = checkDNS.CheckMalwareMHR()
    dns["sans"] = checkDNS.CheckMalwareSans()
    if options.reputation == True:
        doReputation("IpReputation","ip")
        doReputation("DomainReputation","domains")
    doMalware(md5hash)
    ParseThreat(dns,md5hash,options,reportdir)
    pass

def ParseThreat(dns,md5hash,options,reportdir):
    lplugin = LoadPlugins()
    ListPlugins(lplugin)
    results = LoadMethods(lplugin)
    results["dns"] = dns
    jason = convert_json(results)
    data = json.loads(jason)
    (ips,domains) = _ExtractIpDom(data)
    if ips:
        whoisIp = doWhoIp(ips)
        if whoisIp:
            results["WhoisIP"] = whoisIp
    if domains:
        whois = doWhois(domains)
        if whois:
            results["WhoisDomain"] = whois
    reputation = IPReputation(ips)
    FinalReputation = reputation.check()
    if ips:
        maps = Geo(FinalReputation)
        mapa = maps.getUrl()
    domreput = DomainReputation(domains)
    finaldomreput = domreput.check()
    jason = convert_json(results)
    graph = Charts(jason,FinalReputation,finaldomreput)
    graph.PlotVirusTotal()
    graph.GraphData()
    graph.PlotIPReputation()
    graph.PlotDomReputation()
    ###Search HASH in Malware.lu
    parser = ConfigFile()
    url = parser.get("MalwareLu","url")
    api_key = parser.get("MalwareLu","key")
    malwarelu = MalwareLu()
    malwarelu.SearchAndDownload(api_key,md5hash,url)
    if options.json == True:
        try:
            report = codecs.open(os.path.join(COLLECTOR_ROOT, "reports", reportdir,"JSON","{0}.json".format(md5hash)), "w", "utf-8")
            json.dump(results, report, sort_keys=False, indent=4)
            #json.dump(jason, report, sort_keys=False, indent=4)
            report.close()
        except (UnicodeError, TypeError, IOError) as e:
            log.error("Errors in json convert for the hash {0}".format(md5hash))
    if options.docx == True:
        make_word(md5hash,jason,FinalReputation,finaldomreput,reportdir)
    if os.listdir(os.path.join(COLLECTOR_ROOT,"download")):
        srcname = os.listdir(os.path.join(COLLECTOR_ROOT,"download"))
        dstname = os.path.join(COLLECTOR_ROOT,"reports",reportdir,"Download")
        os.chdir(os.path.join(COLLECTOR_ROOT,"download"))
        for files in srcname:
            shutil.move(files,dstname)
        os.chdir(COLLECTOR_ROOT)
    if os.listdir(os.path.join(COLLECTOR_ROOT,"tmpannex")):
        srcname = os.listdir(os.path.join(COLLECTOR_ROOT,"tmpannex"))
        dstname = os.path.join(COLLECTOR_ROOT,"reports",reportdir,"Annex")
        os.chdir(os.path.join(COLLECTOR_ROOT,"tmpannex"))
        for files in srcname:
            shutil.move(files,dstname)
        os.chdir(COLLECTOR_ROOT)


def _ExtractIpDom(data):
    names = [item for item in data]
    ips = list()
    domains = list()
    for name in names:
        try:
            if data[name].__contains__("ipaddress"):
                ips.extend(data[name]["ipaddress"])
            if data[name].__contains__("domains"):
                domains.extend(data[name]["domains"])
        except:
            pass
    ips = list(set(ips))
    domains = list(set(domains))
    return (ips,domains)
    pass

