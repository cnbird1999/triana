#-------------------------------------------------------------------------------
# Name:        Info
# Purpose:     Info to include in final Report
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------

File_Paragraph="""General information about the threat that is shared between websites.
                     Use this to match your suspicious sample and determine if the information
                     provided by this report is or is not accurate."""

Analysis_Information ="""The following section presents antivirus detection of the sample being analysed."""

VirusTotal_info = """VirusTotal scans files using a large number of antiviruses;
                    this is the breakdown of the results. Go to Annex for VirusTotal complete information."""

Files_Paragraph = """ThreatExpert detects which files will be created/modified/deleted if running the sample in your machine:"""

Remote_Conn = """Most viruses and worms perform external connections to C&C to receive orders or to send information.
                Others can connect to external IPs to retrieve updates or missing components. This is a list of the remote
                 IPs and domains related to the threat:"""


File_Information = {"SHA256":"Unknow","SHA1":"Unknow",
                    "Filetype":"Unknow","Size":"Unknow",
                    "Packer":"Unknow","First":"Unknow",
                    "Last":"Unknow","ssdeep":"Unknow",
                    "MD5":"Unknow"}

Files_Created = {}