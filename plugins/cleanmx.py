#-------------------------------------------------------------------------------
# Name:        CLEAN-MX
# Purpose:     Parse CLEAN-MX page. Return an object KEY:VALUE
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
from util.TableParse import parse,clean as limpia
from common.constants import COLLECTOR_ROOT
from lib.download_files import doDownload
import urlparse
from random import randint
tabla =[]
import os
import logging

#<a title="open Url in new Browser at your own risk"

try:
    log = logging.getLogger(__name__)
except:
    pass


class CleanMX:
    def __init__(self):
        self.legend="Extracting data from CleanMX Database..."
        self.ips=list()
        self.domains = list()
        self.dataclean = list()
        self.tabla = list()
        self.genreport = dict()
    def run(self):
        log.info(self.legend)
        try:
            from bs4 import BeautifulSoup
            self.genreport["status"] = True
            fich = open(os.path.join(COLLECTOR_ROOT,"malware","CleanMX"),"r")
            data= fich.read()
            soup = BeautifulSoup(data)
            table = soup.find("table", {'class':'liste'})
            link = table.find("a",{"title":"open Url in new Browser at your own risk !"})
            self.dataclean = parse(str(table))
            self.tabla.append(("URL Added","URL","Status","Ipaddress","IP"))
            tam = len(self.dataclean)
            for i in range (1,tam):
                if self.dataclean[i]!=[]:
                    self.ips.append(self.dataclean[i][10].decode('utf-8').split()[0])
                    self.ips.append(self.dataclean[i][12].decode('utf-8').split()[0])
                    hostname = urlparse.urlparse(self.dataclean[i][7]).hostname
                    self.domains.append(hostname)
                    number = randint(1,1000000)
                    log.info("Try to download file from {0}".format(link["href"],self.dataclean[i][8].decode('utf-8').split()[0]))
                    doDownload(link["href"],str(number),"cleanmx")
                    self.tabla.append((self.dataclean[i][2].decode('utf-8').split()[0],
                                 link["href"],self.dataclean[i][8].decode('utf-8').split()[0],
                                 self.dataclean[i][10].decode('utf-8').split()[0],
                                 self.dataclean[i][12].decode('utf-8').split()[0]))

            #print tabla
            self.genreport["ipaddress"] = self.ips
            self.genreport["domains"] = self.domains
            self.genreport["cleanmx"] = self.tabla
            self.genreport["count"] = 10
            return(self.genreport)
        except:
            log.info("Not found data in Clean-MX Database...")
            self.genreport["status"] = False
            self.genreport["count"] = 0
            return (self.genreport)

    def __del__(self):
        pass