#-------------------------------------------------------------------------------
# Name:        ShadowServer
# Purpose:     Parse ShadowServer. Return an KEY:VALUE object
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
import json
import re
import time
import hashlib
import sys
import os
from common.constants import COLLECTOR_ROOT
import logging

log = logging.getLogger(__name__)


class ShadowServer:
    def __init__(self):
        self.legend="Extracting data from ShadowServer Database..."
        self.genreport = dict()
    def run(self):
        try:
            log.info(self.legend)
            report = open(os.path.join(COLLECTOR_ROOT,"malware","shadowserver"),"r")
            jason = report.readlines()
            if "Whitelisted" in jason[0]:
                data=list(jason[0].split(','))
                line = re.sub('[! ]', '', data[0])
                lista= line.replace(':',',').split(',')
                self.genreport["whitelisted"] = "The hash is WhiteListed by Company {0}, Product {1} and filetype {2}".format(lista[1],data[1],data[2])
                #print "The hash is WhiteListed by Company {0}, Product {1} and filetype {2}".format(lista[1],data[1],data[2])
                self.genreport["count"] = 0
                return self.genreport
            elif "No match" in jason[0]:
                self.genreport["nomatch"] = jason[0].split("!")[1]
                #print jason[0].split("!")[1]
                self.genreport["count"] = 0
                return self.genreport
            else:
                self.genreport["status"] = True
                antivirus_data=list()
                antivirus_data.append(('Antivirus','Results'))
                data= list(jason)
                principal=eval(str(data[0]))
                md5,sha1,first_seen,last_seen,filetype,ssdeep=principal
                self.genreport['md5']=md5
                self.genreport['sha1']=sha1
                self.genreport['First_seen']=first_seen
                self.genreport['last_seen']=last_seen
                self.genreport['filetype']=filetype
                self.genreport['ssdeep']=ssdeep
                elementos= eval(str(data[1]))
                for antivirus in elementos:
                    #print antivirus+":"+elementos[antivirus]
                    #antivirus_data[antivirus]=elementos[antivirus]
                    antivirus_data.append((antivirus,elementos[antivirus]))
                self.genreport["antiviruslist"] = antivirus_data
                self.genreport["count"] = 10
                return self.genreport
        except Exception as e:
            self.genreport["status"]=False
            self.genreport["count"] = 0
            return self.genreport
            log.error(e)
