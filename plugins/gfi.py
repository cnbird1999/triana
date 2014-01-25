#-------------------------------------------------------------------------------
# Name:        GFI
# Purpose:     Parse GFI page. Return an object KEY:VALUE
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------

from lxml import etree,objectify
import urllib
import urllib2
import re
import time
import optparse
import hashlib
import sys
from util.TableParse import parse,clean as limpia
from common.constants import COLLECTOR_ROOT
import os
import socket
import urlparse
import logging

log = logging.getLogger(__name__)

ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

actual = os.getcwd()


class GFISandbox:
    def __init__(self):
        self.ips=list()
        self.domains = list()
        self.legend="Try to extract info from GFI Sandbox"
        self.genreport = dict()
        self.javis=[]
        self.find_tables = []
        self.taxi=[]
        self.regkeys_read=[]
        self.regkeys_change=[]
        self.service_open=[]
        self.sopen = list()
        self.chronological = []
        self.chrono = list()
        self.mutex = []
        self.mutexes = list()
        self.list_summary=[]
        self.status=True
        self.submission = dict()
        self.count = 0
    def run(self):
        try:
            log.info(self.legend)
            from bs4 import BeautifulSoup
            fich = open(os.path.join(COLLECTOR_ROOT,"malware","ssdsandbox"),"r")
            data= fich.read()
            fich.close()
            size = os.path.getsize(os.path.join(COLLECTOR_ROOT,"malware","ssdsandbox"))
            if int(size)==0:
                self.genreport["status"] = False
                log.info("GFI Sandbox log file contains zero data")
                self.genreport["count"] = 0
                return (self.genreport)
            html = data
            error = BeautifulSoup(html)
            try:
                e = error.find('center')
                for i in e:
                    if "Sorry" in e.h3:
                        log.info("Malware not found in GFI Sandbox")
                        self.genreport["count"] = 0
                        self.genreport["status"] = False
                        return (self.genreport)
            except:
                log.info("Seems to be correct in GFI Sandbox log file...")
                self.count +=1
                #genreport.status=True
                java = BeautifulSoup(html)
                soup = BeautifulSoup(html)
                javascript = java.findAll('a',{'id':'whitelink'})
                for i in javascript:
                    self.javis.append(str(i['href']).strip("javascript:toggle"))
                for i in self.javis:
                    self.find_tables.append(i.strip("'()"))
                #Extraer sumario de informe
                subm = BeautifulSoup(html)
                details = subm.findAll('table',{'id':'a_Details:Submission Info'})
                self.list_summary = details
                #Rerorrer todo el HTML para parsear salidas
                for clave in self.find_tables:
                    if clave.startswith('reads'):
                        self.taxi = soup.findAll("td", {'id':clave})
                        for parada in self.taxi:
                            self.regkeys_read= parada.findAll(text=True)
                    if clave.startswith('changes'):
                        self.taxi = soup.findAll("td", {"id":clave})
                        for parada in self.taxi:
                            self.regkeys_change = parada.findAll(text=True)
                    if clave.startswith('open_service'):
                        self.taxi = soup.findAll("td", {"id":clave})
                        for parada in self.taxi:
                            self.service_open = parada.findAll(text=True)
                    if clave.startswith('chron'):
                        self.taxi = soup.findAll("td", {"id":clave})
                        for parada in self.taxi:
                            self.chronological = parada.findAll(text=True)
                    if clave.startswith('create_mutex'):
                        self.taxi = soup.findAll("td", {"id":clave})
                        for parada in self.taxi:
                            self.mutex = parada.findAll(text=True)
                self.count = 5
                ####Extract IPAddress####
                find_ip = soup.findAll('td',{'class':'bodycopy2'})
                ipaddress = re.findall(ipPattern,html)
                self.ips = ipaddress
                self.genreport["ipaddress"] = self.ips
                self.count +=1
                ####Extract domains...####
                possible_link = BeautifulSoup(html)
                entries = possible_link.findAll('a')
                for links in entries:
                    if "dnslookup" in str(links):
                        if "http" in links.text:
                            hostname = urlparse.urlparse(links.text).hostname
                            self.domains.append(hostname)
                        else:
                            hostname = urlparse.urlparse("http://"+links.text).hostname
                            self.domains.append(hostname)
                self.genreport["domains"] = self.domains
                self.count+=1
                ####Parse Submission####
                tabla = parse(str(details))
                tam = len(tabla)
                for i in range(2,tam):
                    if tabla[i]!=[] or tabla[i][0].split('')[0]!="":
                        try:
                            self.submission[tabla[i][0].split(':')[0]] = tabla[i][1]
                        except:
                            next
                self.genreport["submission"] = self.submission
                self.count+=1
                #Comprueba si hay aspectos cronologicos
                if self.chronological:
                    for i in self.chronological:
                         self.chrono.append(i.replace("\n","").replace("\t","").replace(" ",""))
                    self.genreport["chronological"] = self.chrono
                    self.count +=1

                #Comprueba si hay mutex
                if self.mutex:
                    for m in self.mutex:
                        self.mutexes.append(m.replace("\n","").replace("\t","").replace(" ",""))
                    self.genreport["mutexes"] = self.mutexes
                    self.count +=1

                if self.regkeys_change:
                    self.genreport["reg_key_change"] = self.regkeys_change
                    self.count +=1
                if self.regkeys_read:
                    self.genreport["reg_key_read"] = self.regkeys_read
                    self.count +=1
                if self.service_open:
                    for s in self.service_open:
                        self.sopen.append(s.replace("\n","").replace("\t","").replace(" ",""))
                    self.genreport["service_open"] = self.sopen
                    self.count +=1
                if self.count >10:
                    self.count = 10
                self.genreport["count"] = self.count
                return (self.genreport)
        except Exception as e:
            print "An error ocurred with GFI Sandbox...."
            self.genreport["count"] = 0
            return (self.genreport)
            pass

    def __del__(self):
        pass

