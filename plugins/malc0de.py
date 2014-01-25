#-------------------------------------------------------------------------------
# Name:        Malc0de
# Purpose:     Parse Malc0de page. Return an object KEY:VALUE
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
from util.TableParse import parse,clean as limpia
import urlparse
import os
import logging
from common.constants import COLLECTOR_ROOT
from lib.download_files import doDownload

try:
    log = logging.getLogger(__name__)
except:
    pass

class Malc0de:
    def __init__(self):
        self.legend="Trying query to Malc0de Database..."
        self.ips=list()
        self.domains = list()
        self.tabla = list()
        self.count = 0
        self.genreport = dict()
    def run(self):
        try:
            log.info(self.legend)
            from bs4 import BeautifulSoup
            self.genreport["status"] = True
            fich = open(os.path.join(COLLECTOR_ROOT,"malware","malc0de"),"r")
            data= fich.read()
            fich.close()
            soup = BeautifulSoup(data)
            table = soup.find("table", {'class':'prettytable'})
            self.tabla = parse(str(table))
            tam = len(self.tabla)
            if tam >2:
                tmp_list = list()
                tmp_list.append(("date","malware","ipaddress","country","ASN","ASN Name","MD5"))
                for i in range (1,tam):
                    if self.tabla[i]!=[]:
                        self.ips.append(self.tabla[i][2])
                        if self.tabla[i][1].startswith("http"):
                            hostname = urlparse.urlparse(self.tabla[i][1]).hostname
                            self.domains.append(hostname)
                            log.info("Try to download file from {0}".format(self.tabla[i][1]))
                            doDownload(self.tabla[i][1],self.tabla[i][6],"malc0de")
                        else:
                            hostname = urlparse.urlparse("http://"+self.tabla[i][1]).hostname
                            self.domains.append(hostname)
                            log.info("Try to download file from {0}".format("http://"+self.tabla[i][1]))
                            doDownload("http://"+self.tabla[i][1],self.tabla[i][6],"malc0de")

                        tmp_list.append((self.tabla[i][0],self.tabla[i][1],
                        self.tabla[i][2],self.tabla[i][3],self.tabla[i][4],
                        self.tabla[i][5].decode('utf-8','ignore'),
                        self.tabla[i][6]))

                self.genreport["malicious"] = tmp_list
                self.genreport["ipaddress"] = self.ips
                self.genreport["domains"] = self.domains
                self.genreport["count"] = 10
                return(self.genreport)
            else:
                log.info("Not found data in Malc0de Database")
                self.genreport["status"] = False
                self.genreport["count"] = 0
                return self.genreport
        except:
            log.error("Malc0de log not found...")
            self.genreport["status"] = False
            self.genreport["count"] = 0
            return (self.genreport)
    def __del__(self):
        pass
