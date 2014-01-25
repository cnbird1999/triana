#-------------------------------------------------------------------------------
# Name:        ThreatExpert
# Purpose:     Parse ThreatExpert XML Page. Return an object KEY:VALUE
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
import urllib
import urllib2
import re
import time
import optparse
import hashlib
import sys
import os
from urlparse import urlparse
import logging
import base64
from common.constants import COLLECTOR_ROOT

log = logging.getLogger(__name__)
actual = os.getcwd()

class ThreatExpert:
    def __init__(self):
        self.legend="Finding Hash in ThreatExpert Database...."
        self.genreport = {"status":True}
        self.md5 = ""
        self.sha1 = ""
        self.antivirus = {}
        self.size = ""
        self.flag = list()
        self.download_files = list()
        self.category = list()
        self.added_files = list()
        self.added_process = list()
        self.added_modules = list()
        self.regkeys = list()
        self.regvalues = list()
        self.urldownload = list()
        self.hostfile = list()
        self.ipconnect = list()
        self.countries = list()
        self.openurl = list()
        self.status = True
        self.image = ""
        self.mutexes = list()
        self.sample_info = {}
        self.ips = list()
        self.domains = list()
        self.outbound_traffic = list()
        self.internet_connect = list()
        self.count = 0
    def run(self):
        #self.genreport=Reporting()
        from bs4 import BeautifulSoup
        from lxml import etree,objectify
        parser = etree.XMLParser(ns_clean=True)
        report = etree.parse(os.path.join(COLLECTOR_ROOT,"malware","threatexpert"), parser)
        context =  etree.iterparse(os.path.join(COLLECTOR_ROOT,"malware","threatexpert"))
        with open(os.path.join(COLLECTOR_ROOT,"malware","threatexpert")) as f:
                xml = f.read()
        f.close()
        for action,e in context:
            if e.text=='not_found':
                self.genreport["status"]=False
                self.genreport["count"] = 0
        if self.genreport["status"]==False:
            return (self.genreport)
            self.genreport = dict()
        else:
            self.genreport["status"]=True
            self.count +=1
            ###Extract Sample Info###
            root = objectify.fromstring(xml)
            sample = root.subreports.subreport.submission_summary.submission_details.sample_info_collection.sample_info
            for e in sample.iterchildren():
                self.sample_info[e.tag] = e.text
            self.genreport["sample_info"] = self.sample_info
            ###Extract Flag###
            if report.findall("//flag"):
                flags = report.findall("//flag")
                for elements in flags:
                    self.flag.append({elements.findtext('severity'):elements.findtext('description')})
                self.genreport["flags"] = self.flag
                self.count +=1
            ###Extract Know_Threat###
            if report.findall("//known_threat"):
                technical = report.findall("//known_threat")
                for details in technical:
                    #print details.findtext('name')
                    #print details.findtext('description')
                    self.genreport["Threat"] = details.findtext('description')
            if report.findall("//known_threat_category"):
                category = report.findall("//known_threat_category")
                for details in category:
                    self.category.append({details.findtext("name"):details.findtext("description")})
                self.genreport["know_threat"] = self.category
                self.count +=1
            ###Extract files collection###
            try:
                if report.findall("//added_files_collection"):
                    files = report.findall("//added_files_collection")
                    xml_new=(etree.tostring(files[0], pretty_print=True))
                    root = objectify.fromstring(xml_new)
                    tam= len(root.added_file)
                    self.added_files.append(("Filename","MD5","SHA1","Filesize"))
                    for i in range(0,tam):
                        variants= len(root.added_file[i].filenames_collection.filename)
                        for u in range(0,variants):
                            fich=root.added_file[i].filenames_collection.filename[u].text
                        self.added_files.append([fich,root.added_file[i].md5.text,
                                                        root.added_file[i].sha1.text,
                                                        root.added_file[i].filesize.text
                                                     ])

                    self.genreport["added_files"] = self.added_files
                    self.count +=1
            except:
                pass
            ###Extract Process collection###
            try:
                if report.findall("//added_processes_collection"):
                    process = report.findall("//added_process")
                    self.genreport.added_process.append(('ProcName','Filename','Module Size'))
                    for i in process:
                        self.added_process.append((i.findtext("process_name"),
                                                        i.findtext("process_filename"),
                                                        i.findtext("main_module_size")
                                                        ))
                    self.genreport["added_process"] = self.added_process
                    self.count +=1
                if report.findall("//added_modules_collection"):
                    loader = report.findall("//added_module")
                    self.genreport.added_modules.append(('Name','Filename','ProcName','ProcFileName','Start','End'))
                    for i in loader:
                        self.added_modules.append((i.findtext("module_name"),
                                                        i.findtext("module_filename"),
                                                        i.findtext("process_name").replace("[","").replace("]",""),
                                                        i.findtext("process_filename").replace("[","").replace("]",""),
                                                        i.findtext("address_start"),
                                                        i.findtext("address_end")))

                    self.genreport["added_modules"] = self.added_modules
                    self.count +=1
            except:
                pass
            ###Extract RegKeys###
            try:
                if report.findall("//added_regkeys"):
                    reg = report.findall("//added_regkeys")
                    xml_new=(etree.tostring(reg[0], pretty_print=True))
                    root = objectify.fromstring(xml_new)
                    tam= len(root.regkey)
                    for i in range(0,tam):
                        self.regkeys.append(root.regkey[i].text)
                    self.genreport["added_regkeys"] = self.regkeys
                    self.count +=1
                if report.findall("//regvalues_structure"):
                    regkeys = report.findall("//regvalues_structure")
                    regvalues = report.findall("//regvalue")
                    num=0
                    self.regvalues.append(('RegKey','Value','Content'))
                    for i in regkeys:
                        self.regvalues.append([i.findtext("regkey"),
                                                    regvalues[num].findtext("value"),
                                                    regvalues[num].findtext("contents")
                                                    ])

                        num = num+1
                    self.genreport["reg_structure"] = self.regvalues
                    self.count +=1
            except:
                pass
            ###Extract Url###
            try:
                if report.findall("//urldownloadtofile"):
                    downloads = report.findall("//urldownloadtofile")
                    for i in downloads:
                        self.urldownload.append((i.findtext("url"),i.findtext("filename")))
                        urlp = urlparse(i.findtext("url"))
                        self.domains.append(urlp.netloc)
                    self.genreport["domains"] = self.domains
                    self.genreport["url_download"] = self.urldownload
                    self.count +=1
            except:
                pass
            ###Extract host lines###
            try:
                if report.findall("//etc_host_lines"):
                    entry = report.findall("//etc_host_lines")
                    xml_new=(etree.tostring(entry[0], pretty_print=True))
                    root = objectify.fromstring(xml_new)
                    tam= len(root.line)
                    for i in range(0,tam):
                        self.hostfile.append(root.line[i].text)
                    self.genreport["host_file"] = self.hostfile
                    self.count +=1
            except:
                pass
            ###Extract Countries###
            try:
                if report.findall("//countries"):
                    downloads = report.findall("//country")
                    for i in downloads:
                        self.countries.append(i.text)
                    self.genreport["countries"] = self.countries
                    self.count +=1
            except:
                pass
            ###Extract Mutexes###
            try:
                if report.findall("//mutexes"):
                    mutexes = report.findall("//mutex")
                    for i in mutexes:
                        self.mutexes.append(i.text)
                    self.genreport["mutexes"] = self.mutexes
                    self.count +=1
            except:
                pass
            ###Extract Connect IP###
            try:
                if report.findall("//connect_ip"):
                    ip = report.findall("//connect_ip")
                    self.ipconnect.append(('IP Address','Port Number'))
                    for i in ip:
                        self.ipconnect.append([i.findtext("ip"),i.findtext("port_number")])
                        self.ips.append(i.findtext("ip"))
                    self.genreport["ipconnect"] = self.ipconnect
                    self.genreport["ipaddress"] = self.ips
                    self.count +=1
            except:
                pass
            ###Extract OpenUrl
            try:
                if report.findall("//technical_details"):
                    connect = report.findall("//technical_details")
                    xml_new=(etree.tostring(connect[0], pretty_print=True))
                    tree = etree.fromstring(xml_new,parser)
                    urls = tree.findall("internetopenurl_api")
                    for url in range(0,len(urls[0])):
                        self.download_files.append(urls[0][url].text)
                    self.genreport["download_files"] = self.download_files
                    self.count +=1
            except:
                pass
            ###Extract Images###
            try:
                root = objectify.fromstring(xml)
                for e in root.subreports.subreport.technical_details.screen_gif:
                    self.genreport["screen"] = e.text
                    outfile = open(os.path.join(COLLECTOR_ROOT,"tmp","threatexpert.gif"),"wb")
                    outfile.write(base64.b64decode(self.genreport["screen"]))
                    outfile.close()
                    self.count +=1
            except:
                pass
            ###Extract OpenUrl
            try:
                if report.findall("//gethostbyname_api"):
                    connect = report.findall("//host")
                    for domain in connect:
                        self.domains.append(domain.text)
                    self.genreport["domains"] = self.domains
                    self.count +=1
            except:
                pass
            ###Outbound Connections###
            try:
                if report.findall("//outbound_traffic"):
                    entry = report.findall("//textlines_collection")
                    port = report.findall("//outbound_traffic_element")
                    xml_port = (etree.tostring(port[0], pretty_print=True))
                    root_port = objectify.fromstring(xml_port)
                    xml_new=(etree.tostring(entry[0], pretty_print=True))
                    root = objectify.fromstring(xml_new)
                    tam= len(root.textline)
                    for i in range(0,tam):
                        self.outbound_traffic.append(root.textline[i].text)
                    self.genreport["outbound_traffic"] = self.outbound_traffic
                    self.genreport["port_connection"] = root_port.port_number[0].text
                    self.count +=1
            except:
                pass
            ###Internet Connect####
            try:
                if report.findall("//internetconnect_api"):
                    entry = report.findall("//internetconnect")
                    self.internet_connect.append(('Server','Port Number', 'User', 'Password'))
                    for parameter in entry:
                        self.internet_connect.append([parameter.findtext('server'),
                        parameter.findtext('port_number',parameter.findtext('user_name'),
                        parameter.findtext('password'))])
                    self.genreport["internet_connect"] = self.internet_connect
                    self.count +=1
            except:
                pass

            if self.count >10:
                self.count = 10
            self.genreport["count"] = self.count
            return (self.genreport)

def __del__(self):
    pass