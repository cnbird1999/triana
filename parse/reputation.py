#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      Silverhack
#
# Created:     22/05/2012
# Copyright:   (c) Silverhack 2012
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import sys
import os
from common.config import ConfigFile
from common.constants import COLLECTOR_ROOT
import logging
import time

actual = os.getcwd()
log = logging.getLogger(__name__)

class IPReputation:
    def __init__(self,ipaddress):
        self.legend="\nAnalyze IP Reputation...."
        self.ipaddress = ipaddress
        self.FinalReputation =list()

    def generateDict(self):
        newdict = dict()
        parser = ConfigFile()
        for i in parser.options("IpReputation"):
            newdict[i] = False
            #reputationlist[i] = False
        return newdict

    def check(self):
        log.info(self.legend)
        parser = ConfigFile()
        for foundip in self.ipaddress:
            reputation = dict()
            tmp = self.generateDict()
            reputation["status"] = False
            detected = 0
            nodetected = 0
            for i in parser.options("IpReputation"):
                try:
                    fich = open(os.path.join(COLLECTOR_ROOT,"ip",i+'.txt'),'r')
                    for ip in fich:
                        if foundip in ip:
                            tmp[i] = True
                            reputation["status"] = True
                    fich.close()
                except IOError:
                    log.warning("The Reputation list %s not downloaded " %i)
                    tmp[i] = "NotDownload"
            for key,value in tmp.items():
                if value == True:
                    detected +=1
                else:
                    nodetected +=1
            reputation["detected"] = detected
            reputation["nodetected"] = nodetected
            self.FinalReputation.append((foundip,tmp,reputation))
            #print self.FinalReputation
        return self.FinalReputation

"""ipadd = list()
ipadd.append("60.191.170.188")
ipadd.append("219.139.108.15")
ipadd.append("192.5.5.241")
ipadd.append("42.96.138.138")
reputation = IPReputation(ipadd)
FinalReputation = reputation.check()
for ip,reputation,status in FinalReputation:
    print ip
    print status"""

