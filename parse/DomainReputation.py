#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      Silverhack
#
# Created:     28/05/2012
# Copyright:   (c) Silverhack 2012
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import sys
import os
from common.config import ConfigFile
from common.constants import COLLECTOR_ROOT
import logging

try:
    log = logging.getLogger(__name__)
except:
    pass

actual = os.getcwd()

class DomainReputation:
    def __init__(self,domaddress):
        self.legend="\nAnalyze domain Reputation...."
        self.domaddress = domaddress
    def generateDict(self):
        DomainInvestigate = {}
        parser = ConfigFile()
        for i in parser.options("DomainReputation"):
            DomainInvestigate[i] = False
        return DomainInvestigate

    def check(self):
        FinalReputationDomains = list()
        log.info(self.legend)
        parser = ConfigFile()
        for founddomain in self.domaddress:
            reputation = dict()
            DomainInvestigate = self.generateDict()
            reputation["status"] = False
            detected = 0
            nodetected = 0
            for i in parser.options("DomainReputation"):
                try:
                    fich = open(os.path.join(COLLECTOR_ROOT,"domains",i)+'.txt','r')
                    for domain in fich:
                        if str(founddomain) in domain:
                            #log.info("Domain Address %s found in %s Reputation List" %(founddomain,i))
                            DomainInvestigate[i]=True
                            reputation["status"] = True
                    fich.close()
                except IOError:
                    log.error("The Reputation list %s not downloaded " %i)
                    DomainInvestigate[i]='Not Download'
            for key,value in DomainInvestigate.items():
                if value == True:
                    detected +=1
                else:
                    nodetected +=1
            reputation["detected"] = detected
            reputation["nodetected"] = nodetected
            FinalReputationDomains.append((founddomain,DomainInvestigate,reputation))
        return FinalReputationDomains


"""dominios = list()
dominios.append("3apa3a.tomsk.tw")
dominios.append("ageprim.enamax.net")
reputation = DomainReputation(dominios)
FinalReputationDomains = reputation.check()
print FinalReputationDomains"""

