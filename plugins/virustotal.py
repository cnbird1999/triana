#-------------------------------------------------------------------------------
# Name:        VirusTotal
# Purpose:     GET VirusTotal Query. Return an JSON object
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------

import json
import urllib
import urllib2
import re
import time
import optparse
import hashlib
import sys
import os
import logging
from common.constants import COLLECTOR_ROOT

log = logging.getLogger(__name__)

class VirusTotal:
    def __init__(self):
        self.legend="Trying query with VirusTotal Database..."
    def run(self):
        try:
            virustotal = dict()
            log.info(self.legend)
            report = open(os.path.join(COLLECTOR_ROOT,"malware","virustotal"),'r')
            jason = report.readline()
            response_code = json.loads(jason).get("response_code")
            if response_code ==1:
                log.info("Data found in VirusTotal Database...")
                scandict = {}
                scanlist = list()
                scans = json.loads(jason).get("scans")
                virustotal["total_av"] = json.loads(jason).get("total")
                virustotal["positives"] = json.loads(jason).get("positives")
                virustotal["permalink"] = json.loads(jason).get("permalink")
                virustotal["sha1"] = json.loads(jason).get("sha1")
                virustotal["sha256"] = json.loads(jason).get("sha256")
                virustotal["md5"] = json.loads(jason).get("md5")
                virustotal["scan_date"] = json.loads(jason).get("scan_date")
                scanlist.append(("Antivirus_Name","Detection","Version","Result","Update"))
                for key,value in scans.iteritems():
                    scanlist.append((key,str(value["detected"]),value["version"],value["result"],value["update"]))
                virustotal["results"] = scanlist
                return (virustotal)
            else:
                log.error("Virustotal report not found...")
                virustotal["results"] = False
                return (virustotal)
        except:
            log.error("Error in VirusTotal...")
            virustotal["results"] = False
            return (virustotal)
