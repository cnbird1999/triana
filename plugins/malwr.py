#-------------------------------------------------------------------------------
# Name:        malwr
# Purpose:     Parse Malwr page. Return an object KEY:VALUE
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
import base64
import cgi
import os
import sys
from util.TableParse import parse,clean as limpia
from common.constants import COLLECTOR_ROOT
import re
from random import randint
import json
import logging
import requests

log = logging.getLogger(__name__)

class Malwr:
    def __init__(self):
        self.legend="Data extracted from Malwr.com...."
        self.info = dict()
        self.files = list()
        self.regkeys = list()
        self.mutexes = list()
        self.strings = ""
        self.dropped_files = list()
        self.network_stats = dict()
        self.behavior = ""
        self.http_requests = list()
        self.dns_requests = list()
        self.file_info = dict()
        self.pe_sections = list()
        self.pe_resources = list()
        self.status = False
        self.pe_imports = list()
        self.ips = list()
        self.doms = list()
        self.count = 0
        self.tmp_count = 0
        self.genreport = dict()
        self.signatures = list()
        self.screenshots = list()
        self.contador = 0
        self.tmp = list()
        self.irc = list()
        self.smtp = list()

    def run(self):
        from bs4 import BeautifulSoup
        try:
            infile = open(os.path.join(COLLECTOR_ROOT,"malware","malwr"),"r")
            data = infile.read()
            infile.close()
            soup = BeautifulSoup(data)
            ###Analysis Part
            try:
                self.genreport["status"] = True
                div = soup.find("div",{"class":"box-content"})
                if div:
                    table = div.find("table")
                    static = parse(str(table))
                    for i in range(1,len(static)):
                        if static[i]!=[]:
                            self.info["Category"] = static[i][0]
                            self.info["Started"] = static[i][1]
                            self.info["Completed"] = static[i][2]
                            self.info["Duration"] = static[i][3]
                    self.genreport["analysisinfo"] = self.info
            except:
                log.error("Problem in malwr plugin in analysis section")
            ###Details Part
            try:
                div = soup.find("section",{"id":"file"})
                if div:
                    table = div.find("table")
                    static = parse(str(table))
                    keys = list()
                    values = list()
                    keys = static[0]
                    for i in range(1,len(static)):
                        values.append("".join(str(static[i][0])))
                    dictionary = dict(zip(keys, values))
                    self.genreport["details"] = dictionary
                    if "Download" in values:
                        malware = soup.find("a",{"class":"btn btn-primary btn-small"})
                        from auth.malwrauth import MalwrAuth
                        from common.config import ConfigFile
                        parser = ConfigFile()
                        username = parser.get("MalwrAuth","username")
                        password = parser.get("MalwrAuth","password")
                        auth = MalwrAuth()
                        auth.login(auth.urllogin,username,password)
                        auth.download_malware(malware["href"])

            except Exception as e:
                log.error("Problem in malwr plugin in details section")
                print e
            ###Signature Part
            try:
                sig = soup.find("section",{"id":"signatures"})
                if sig:
                    div = sig.findAll("div",{"class":re.compile("^alert")})
                    for i in div:
                        self.signatures.append(i.text.strip())
                    self.genreport["signatures"] = self.signatures
                    #print self.signatures
            except:
                log.error("Problem in malwr plugin in signature section")
            ###Screenshots
            try:
                scr = soup.find("section",{"id":"screenshots"})
                href = scr.findAll("a",{"rel":"lightbox"})
                if href:
                    for link in href:
                        self.screenshots.append("https://malwr.com/"+link["href"])
                    #print self.screenshots
                    self.genreport["screenshots"] = self.screenshots
                    tmpimg = list()
                    count = 0
                    for screen in self.screenshots:
                        img = requests.get(screen)
                        tmpimg.append(base64.b64encode(img.content))
                        outfile = open(os.path.join(COLLECTOR_ROOT,"tmp",str(count)+".png"),"wb")
                        outfile.write(img.content)
                        count+=1
                        outfile.close()
                    self.genreport["images"] = tmpimg
            except Exception as error:
                log.debug(error)
                log.error("Problem in malwr plugin in screenshots section")
            ###Domains
            try:
                dm = soup.find("section",{"id":"domains"})
                table = dm.find("table")
                if table:
                    static = parse(str(table))
                    for i in range(1,len(static)):
                        if static[i]!=[]:
                            self.doms.append(static[i][0])
                            self.ips.append(static[i][1])
                self.genreport["domains"] = self.doms
                self.genreport["ipaddress"] = self.ips
                    #print self.doms
                    #print self.ips
            except:
                log.error("problem with malwr plugin in section domain")
            ###IRC
            try:
                dm = soup.find("div",{"class":"tab-pane fade","id":"network_irc_tab"})
                if dm.pre:
                    for line in dm.pre.contents:
                        self.irc.append(line.extract())
                        #print cgi.escape(line.extract())
                    self.genreport["irc"] = self.irc
            except Exception as e:
                log.error("problem with malwr plugin in section IRC")
                #print e

            ###SMTP
            try:
                dm = soup.find("div",{"class":"tab-pane fade","id":"network_smtp_tab"})
                if dm.pre:
                    for line in dm.pre.contents:
                        self.smtp.append(line.extract())
                        print cgi.escape(line.extract())
                    self.genreport["smtp"] = self.smtp
            except Exception as e:
                log.error("problem with malwr plugin in section SMTP")
                #print e

            ###Section Summary
            try:
                sm = soup.find("section",{"id":"summary"})
                fl = sm.find("div",{"id":"summary_files"})
                tfiles = fl.find("div",{"class":"well mono"})
                if tfiles:
                    for files in tfiles.findAll(text=True):
                        self.files.append(files.strip())
                    #print self.files
                    self.genreport["files"] = self.files
            except:
                log.error("Problem with malwr plugin in summary files")
            ###Section Registry Keys
            try:
                rg = sm.find("div",{"id":"summary_keys"})
                rkeys = rg.find("div",{"class":"well mono"})
                if rkeys:
                    for key in rkeys.findAll(text=True):
                        self.regkeys.append(key.strip())
                    #print self.regkeys
                    self.genreport["regkeys"] = self.regkeys
            except:
                log.error("Problem with malwr plugin in section regkeys")
            ###Section Summary Mutexex
            try:
                m = sm.find("div",{"id":"summary_mutexes"})
                mutexes = m.find("div",{"class":"well mono"})
                if mutexes:
                    for mutex in mutexes.findAll(text=True):
                        self.mutexes.append(mutex.strip())
                    #print self.mutexes
                    self.genreport["mutexes"] = self.mutexes
            except:
                log.error("Problem in malwr plugin in mutex section")
            ###Section Static Analysis
            try:
                st = soup.find("div",{"id":"pe_sections"})
                if st:
                    table = st.find("table")
                    static = parse(str(table))
                    for i in range(0,len(static)):
                        if static[i]!=[]:
                            self.pe_sections.append((static[i][0],static[i][1],static[i][2],
                                                    static[i][3],static[i][4]))
                    #print self.pe_sections
                    self.genreport["pe_sections"] = self.pe_sections
            except:
                log.error("Problem in malwr plugin in pe section")
            ###Section PE info
            try:
                div = soup.find("section",{"id":"static_analysis"})
                if div:
                    table = div.find("div",{"id":"pe_versioninfo"})
                    if table:
                        static = parse(str(table))
                        keys = list()
                        values = list()
                        keys = static[0]
                        for i in range(1,len(static)):
                            values.append("".join(str(static[i][0])))
                        dictionary = dict(zip(keys, values))
                        self.genreport["versioninfo"] = dictionary
            except Exception as e:
                log.error("Problem in malwr plugin in PE info")
                print e
            ###PE Imports
            try:
                imp = soup.find("div",{"id":"pe_imports"})
                if imp:
                    Allimports = imp.findAll("div",{"class":"well"})
                    tmpdict = dict()
                    if Allimports:
                        for imports in Allimports:
                            tmplist = list()
                            library = imports.div.strong.text.split()[1]
                            tmplist.append(("Library","Offset","Call"))
                            for imps in imports.findAll("span",{"class":"mono"}):
                                tmpdict[imps.text.split()[0]] =imps.text.split()[1]
                                tmplist.append((str(library.strip()),
                                               imps.text.split()[0],
                                               imps.text.split()[1]))
                            self.pe_imports.append((library,tmpdict))
                            self.tmp.append(tmplist)
                        #print self.pe_imports
                        self.genreport["pe_imports"] = self.tmp
            except Exception as e:
                print e
                log.error("Problem in malwr plugin in pe imports")
            ###PE Strings
            try:
                strsection = soup.find("section",{"id":"static_strings"})
                Allstr = strsection.find("div",{"class":"well"})
                for string in Allstr.findAll(text=True):
                    self.strings+= "".join(string)
                tmpout = open(os.path.join(COLLECTOR_ROOT,"tmpannex","strings.txt"),"w")
                tmpout.write(self.strings)
                tmpout.close()
                #print self.strings
                self.genreport["strings"] = self.strings
            except:
                log.error("Problem in malwr plugin in strings section")
            ####Behavioral Section
            try:
                script = soup.find('script', text=re.compile('graph_raw_data'))
                if script:
                    json_text = script.text.split("=")[1].strip()
                    jsonobject = json.loads(json_text[:-1])
                    self.behavior = jsonobject
                    """for behav in self.behavior:
                        for key,value in behav.items():
                            print key+" "+str(value)"""
                    self.genreport["behavior"] = self.behavior
            except:
                log.error("Problem in malwr plugin in behavior javascript")
            ###Network Section
            try:
                ipnet = soup.find("div",{"id":"network_hosts_tab"})
                table = ipnet.find("table")
                if table:
                    static = parse(str(table))
                    for i in range(1,len(static)):
                        if static[i]!=[]:
                            self.ips.append(static[i][0])
            except:
                log.error("Problem in malwr plugin in network host tab")
            ###Network Requests
            try:
                req = soup.find("div",{"id":"network_http_tab"})
                table = req.find("table")
                if table:
                    static = parse(str(table))
                    for i in range(0,len(static)):
                        if static[i]!=[]:
                            self.http_requests.append(static[i])
                    #print self.http_requests
                    self.genreport["http_requests"] = self.http_requests
            except:
                log.error("Problem in malwr plugin in http requests")
            ###Dropped files
            try:
                dropfiles = soup.find("div",{"id":"dropped"})
                dropAll = dropfiles.findAll("div",{"class":"box"})
                if dropAll:
                    for drp in dropAll:
                        table = drp.find("table")
                        static = parse(str(table))
                        keys = list()
                        values = list()
                        keys = static[0]
                        for i in range(1,len(static)):
                            if static[i]!=[]:
                                values.append("".join(str(static[i][0])))
                        dictionary = dict(zip(keys, values))
                        self.dropped_files.append(dictionary)
                    #print self.dropped_files
                    self.genreport["dropped_files"] = self.dropped_files
            except:
                log.error("Problem in malwr plugin in dropped files")
            self.genreport["count"] = 10
            return self.genreport
        except IOError:
            self.genreport["count"] = 0
            return self.genreport
            log.error("Malwr file not found...")

    def __del__(self):
        pass


"""malware = Malwr()
malware.run()"""
