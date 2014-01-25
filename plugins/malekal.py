#-------------------------------------------------------------------------------
# Name:        Malekal
# Purpose:     Parse Malekal page. Return an object KEY:VALUE
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
from util.TableParse import parse,clean as limpia
import urlparse
import os
import re
import logging
from lib.download_files import doDownload
from common.constants import COLLECTOR_ROOT

log = logging.getLogger(__name__)

ip = re.compile('(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}'
                +'(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))')



class Malekal:
    def __init__(self):
        self.legend="Extracting data from Malekal Database..."
        self.ips=list()
        self.domains = list()
        self.tabla = list()
        self.data = dict()
        self.count = 0
        self.urls = list()
        self.genreport = dict()
    def run(self):
        log.info(self.legend)
        try:
            from bs4 import BeautifulSoup
            fich = open(os.path.join(COLLECTOR_ROOT,"malware","malekal"),"r")
            data= fich.read()
            fich.close()
            soup = BeautifulSoup(data)
            table = soup.find("table")
            if len(table)>1:
                log.info("Possible data found in malekal...")
                self.count+=2
                self.tabla = parse(str(table))
                try:
                    self.data["date"] = self.tabla[2][1]
                except:
                    pass
                try:
                    self.data["size"] = self.tabla[2][3]
                except:
                    pass
                try:
                    values = self.tabla[2][2].split(":")
                    self.data["md5"] = values[1][:-4]
                    log.info("Try to donwload possible files....")
                    doDownload("http://malwaredb.malekal.com/files.php?file={0}".format(self.data["md5"].split()[0]),".zip","malekal")
                    self.data["sha1"] = values[2]
                except:
                    pass
                try:
                    a = self.tabla[2][4].split(":")
                    self.data["antivirus"] = a[0]
                    self.data["antivirus_value"] = a[2]
                except:
                    pass
                try:
                    d = self.tabla[2][5].split(":")
                    self.data["FileDetection"] = d[1]
                except:
                    pass
                try:
                    u = self.tabla[2][6].split()
                    count = 0
                    for url in u:
                        if url.startswith("http"):
                            self.urls.append(url)
                            self.domains.append(urlparse.urlparse(url).hostname)
                            log.info("Found domain in Malekal...")
                            self.count+=1
                        if "Comment" in url:
                            self.data["comment"] = u[count+1]
                        elif "ASN" in url:
                            self.data["asn"] = u[count+1]
                        elif "Netname" in url:
                            self.data["netname"] = u[count+1]
                        match = ip.search(url)
                        if match:
                            self.ips.append(match.group())
                            self.count+=1
                except:
                    pass
                self.data["ipaddress"] = self.ips
                self.data["domains"] = self.domains
                self.genreport = self.data
                self.genreport["status"] = True
                self.genreport["count"] = 10
                return (self.genreport)
            else:
                self.genreport["status"] = False
                self.genreport["count"] =0
                return (self.genreport)
                log.error("No data found in Malekal...")
        except IOError as e:
            log.error("No such file or directory...")
            log.error(e)
            self.genreport["count"] = 0
            self.genreport["status"] = False
            return (self.genreport)
    def __del__(self):
        pass







"""ips = list()
doms = list()
malcode = Malekal(ips,doms)
datos,ipes = malcode.Fetch()
print datos"""
