#-------------------------------------------------------------------------------
# Name:        Config
# Purpose:     Read config file
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
from common.constants import COLLECTOR_ROOT
from ConfigParser import SafeConfigParser
import codecs
import os
import sys
import logging

log = logging.getLogger(__name__)

def ConfigFile():
    try:
        parser = SafeConfigParser()
        config_path = os.path.join(COLLECTOR_ROOT,"conf","conf.ini")
        with codecs.open(config_path,"r",encoding="utf-8") as f:
            parser.readfp(f)
        return parser
    except:
        log.error("Error trying to read the configuration file")
        sys.exit()