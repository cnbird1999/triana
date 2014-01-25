#-------------------------------------------------------------------------------
# Name:        Xandora
# Purpose:     Parse Xandora page. Return an object KEY:VALUE
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
import re
import time
import hashlib
import sys
from util.TableParse import parse,clean as limpia
import os
from common.constants import COLLECTOR_ROOT
import logging

log = logging.getLogger(__name__)

actual = os.getcwd()

class PandaSecurity:
    def __init__(self):
        self.legend='Try to extract information from Xandora Network....'
        self.genreport = dict()
        self.malware_name='Unknow'
        self.details={}
        self.headers = 'Unknow'
        self.Registry_changes = list()
        self.Process = list()
        self.Changes = list()
        self.found = False
        self.count = 0
    def run(self):
        try:
            from bs4 import BeautifulSoup
            log.info(self.legend)
            fich = open(os.path.join(COLLECTOR_ROOT,"malware","xandora"),'r')
            html = fich.read()
            fich.close()
            soup = BeautifulSoup(html)
            status = soup.title.string
            if len(status) < 32:
                self.genreport["status"] = False
                self.genreport["count"] = 0
                return self.genreport
            else:
                self.genreport["status"] = True
                malware = soup.find('div',{'class':'grid_6'})
                self.genreport["malware_name"] = str(malware.text).split()[0]
                t1=soup.find('table',{'style':'margin: 1em;'})
                details = parse(str(t1))
                tam = len(details)
                for i in range(0,tam):
                    if len(details[i])==2:
                        self.details[details[i][0]]=details[i][1]
                        #print details[i][0]+":"+details[i][1]
                self.genreport["details"] = self.details
                headers = soup.findAll('fieldset')
                for i in headers:
                    if (i.text).find('++++++++++++++++++++++++ FILE HEADER INFORMATION +++++++++++++++++++++++++')!=-1 or (i.text).find('++++++++++++++++++++++++++++++++ SECTIONS ++++++++++++++++++++++++++++++++')!=-1:
                        self.genreport["headers"] = i.text
                        #print i.text
                alltables = soup.findAll('table',{'id':'list'})
                lentables =  len(alltables)
                for i in range(0,lentables):
                    if alltables[i].th.text=='Action':
                        reg = parse(str(alltables[i]))
                        self.genreport["Registry_changes"] = reg

                    if alltables[i].th.text=='PID':
                        pid = parse(str(alltables[i]))
                        self.genreport["Process"] = pid

                    if alltables[i].th.text=='MD5':
                        change = parse(str(alltables[i]))
                        self.genreport["changes"] = change
                self.genreport["count"] = 10
                return self.genreport
        except:
            log.error("An error ocurred with Xandora Network...")
            self.genreport["status"] = False
            self.genreport["count"] = 0
            return self.genreport
            pass