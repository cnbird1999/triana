#-------------------------------------------------------------------------------
# Name:        Triana
# Purpose:     Threat Intelligent Analysis
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/07/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
import sys
try:
    import dns.name
    import dns.query
    import dns.resolver
    from dns.exception import DNSException, Timeout
except ImportError as error:
    print "You don't have module {0} installed".format(error.message[16:])
    print "You need install dnspython. Please download at http://www.dnspython.org/"
    #sys.exit()
try:
    from bs4 import BeautifulSoup
except ImportError as error:
    print "You don't have module {0} installed".format(error.message[16:])
    print "You need install python BeautitulSoup. Please download at http://www.crummy.com/software/BeautifulSoup/#Download"
    #sys.exit()
try:
    import requests
except ImportError as error:
    print "You don't have module {0} installed".format(error.message[16:])
    print "You need install python requests. Please download at http://docs.python-requests.org/en/latest/"
    #sys.exit()

try:
    import tldextract
except ImportError as error:
    print "You don't have module {0} installed".format(error.message[16:])
    print "You need install python tldextract. Please download at https://pypi.python.org/pypi/tldextract/0.2"
    #sys.exit()

try:
    import cairoplot
except ImportError as error:
    print "You don't have module {0} installed".format(error.message[16:])
    print "You need install python cairoplot. Please download at https://github.com/rodrigoaraujo01/cairoplot"
    print "You need install python cairo. Please download at http://www.lfd.uci.edu/~gohlke/pythonlibs/#pycairo"
    #sys.exit()

try:
    from lxml import etree
except ImportError as error:
    print "You don't have module {0} installed".format(error.message[16:])
    print "You need install python lxml. Please download at http://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml"
    #sys.exit()

try:
    from PIL import Image
except ImportError as error:
    print "You don't have module {0} installed".format(error.message[16:])
    print "You need install python PIL. Please download at http://www.lfd.uci.edu/~gohlke/pythonlibs/#pil"
    #sys.exit()

try:
    import pygeoip
except ImportError as error:
    print "You don't have module {0} installed".format(error.message[16:])
    print "You need install pygeoip. Please download at https://github.com/appliedsec/pygeoip"
    #sys.exit()
from util.utils import *
from util.startup import *
from common.config import ConfigFile
from common.constants import COLLECTOR_ROOT
from common.loader import *
from optparse import OptionParser
from optparse import OptionGroup
from parse.reputation import *
from parse.DomainReputation import *
import time
import re
import logging
import json
from reporting.docxreport import make_word
from util.whois import doWhois
from util.whoisIp import doWhoIp
from util.charts import Charts
try:
    log = logging.getLogger(__name__)
except:
    pass

start = time.time()

folders = ["malware",
               "charts",
               "domains",
               "ip",
               "download",
               "tmp"]

folders2 = ["malware",
               "charts",
               "download",
               "tmp",
               "tmpannex"]

def main():
    #set up command-line options

    parser = OptionParser(description="Threat Intelligent Analysis Tool | http://windowstips.wordpress.com", version="Triana 0.1")
    StandardExtractGroup = OptionGroup(parser, "Analysis Section", "Perform a Internet Search. This include extract all data from Knows sites")
    StandardExtractGroup.add_option("-f","--file",action="store", help="File name to perform query",dest="filename")
    StandardExtractGroup.add_option("-m","--md5", action="store",help="MD5 Hash File to perform query",dest="Md5Hash")
    StandardExtractGroup.add_option("-l","--list",action="store", help="Analyze an MD5 Hash list file",dest="ListHash")
    parser.add_option_group(StandardExtractGroup)
    ReportsOptions = OptionGroup(parser, "Reporting Options", "Options to perform a full Reporting")
    ReportsOptions.add_option("-d", "--docx", action = "store_true",help="Perform report in DOCX Format", default = False)
    ReportsOptions.add_option("-j", "--json", action = "store_true",help="Save report in JSON Format", default = False)
    parser.add_option_group(ReportsOptions)
    ExtraOptions = OptionGroup(parser, "Options", "Options to analyze")
    ExtraOptions.add_option("-r","--reputation",action = "store_true", help="Download all reputation list. Also include IP and Domain",default = False)
    ExtraOptions.add_option("-v","--verbosity",action = "store",
                            help="Show message information in shell. Values supported are info,debug,critical,error,warning",
                            dest="logging")
    parser.add_option_group(ExtraOptions)
    Misc = OptionGroup(parser, "Information", "Options to show information")
    Misc.add_option("-s","--sources",help="Show source list",dest="sources")
    parser.add_option_group(Misc)
    #grab options
    (options, args) = parser.parse_args()
    if (options.Md5Hash):
        if re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', options.Md5Hash)==[]:
            parser.error("Invalid MD5")
            sys.exit()
        else:
            try:
                md5 = options.Md5Hash
                delete_tmp(root = COLLECTOR_ROOT, folders = folders2)
                delete_media(root= COLLECTOR_ROOT)
                reportdir = Create_Structure(md5)
                if options.logging:
                    init_logging(options.logging)
                Triana(md5,options,reportdir)
                #ParseThreat(md5,options)
            except KeyboardInterrupt:
                sys.exit()
    elif (options.filename):
        md5 = HashingMalware(options.filename)
        if md5:

            delete_tmp(root = COLLECTOR_ROOT, folders = folders2)
            delete_media(root= COLLECTOR_ROOT)
            reportdir = Create_Structure(md5)
            if options.logging:
                init_logging(options.logging)
            Triana(md5,options,reportdir)
            #ParseThreat(md5,options)
    elif (options.ListHash):
        try:
            infile = open(options.ListHash,"r")
            for md5 in infile:
                delete_tmp(root = COLLECTOR_ROOT, folders = folders2)
                delete_media(root= COLLECTOR_ROOT)
                reportdir = Create_Structure(md5.split()[0])
                if options.logging:
                    init_logging(options.logging)
                Triana(md5.split()[0],options,reportdir)
                #ParseThreat(md5.split()[0],options)
            infile.close()
        except IOError:
            log.error("The file {0} has not found...".format(options.ListHash))


if __name__ == '__main__':
    main()
    print "\nElapsed Time: %s" % (time.time() - start)
