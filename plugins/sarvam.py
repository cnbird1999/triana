#-------------------------------------------------------------------------------
# Name:        Sarvam
# Purpose:     Parse Sarvam page. Read JSON file
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
import json
import os
import sys
import requests
import logging
from common.constants import COLLECTOR_ROOT

log = logging.getLogger(__name__)

class Sarvam:
    def __init__(self):
        self.legend="Trying query with Sarvam Database..."
    def run(self):
        sarvam = dict()
        sarvam["count"] = 0
        try:
            log.info(self.legend)
            report = open(os.path.join(COLLECTOR_ROOT,"malware","sarvam"),"r")
            jason = report.readline()
            response_code = json.loads(jason).get("result")
            if response_code["info"].__contains__("error"):
                log.info(response_code["info"]["error"])
                return sarvam
            else:
                sarvam["size"] = response_code["info"]["size"]
                sarvam["md5"] = response_code["info"]["md5"]
                sarvam["image"] = response_code["info"]["image_url"]
                sarvam["virustotal"] = response_code["info"]["virustotal_report"]
                sarvam["count"] = 10
                image_download = requests.get(sarvam["image"])
                out = open(os.path.join(COLLECTOR_ROOT,"tmp","sarvam.png"),"wb")
                out.write(image_download.content)
                out.close()
                return sarvam
        except Exception as error:
            log.error("Error in plugin Sarvam")
            return sarvam