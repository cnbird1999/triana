#-------------------------------------------------------------------------------
# Name:        MalwrAuth
# Purpose:     Class to auth in Malwr.com.
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
import sys,os
from common.constants import COLLECTOR_ROOT
import requests
import codecs
from random import randint
from bs4 import BeautifulSoup

class MalwrAuth:
    def __init__(self):
        self.client = False
        self.urllogin = 'https://malwr.com/account/login/'
        self.urlsearch = 'https://malwr.com/analysis/search/'
    def login(self,login_url,username,password):
        try:
            self.client = requests.session()
            # Retrieve the CSRF token first
            self.client.get(self.urllogin)  # sets cookie
            csrftoken = self.client.cookies['csrftoken']
            login_data = dict(username=username, password=password, csrfmiddlewaretoken=csrftoken, next='/')
            r = self.client.post(self.urllogin, data=login_data, headers=dict(Referer=self.urllogin))
        except requests.ConnectionError:
            pass


    def search(self,search):
        s = self.client.get(self.urlsearch)  # sets cookie
        soup = BeautifulSoup(s.text)
        csrf_input = soup.find(attrs = dict(name = 'csrfmiddlewaretoken'))
        csrf_token = csrf_input['value']
        payload = {'csrfmiddlewaretoken': csrf_token, 'search': search}
        search = self.client.post(self.urlsearch,data=payload,headers=dict(Referer=self.urlsearch))
        return search

    def find_report(self,html):
        soup = BeautifulSoup(html.text)
        csrf_input = soup.find(attrs = dict(name = 'csrfmiddlewaretoken'))
        csrf_token = csrf_input['value']
        payload = {"csrftoken":csrf_token}
        founds = soup.find("div",{"class":"box-content"})
        if founds:
            reports = founds.find("a")
            html = self.client.get("https://malwr.com"+ reports["href"],params=payload,headers=dict(Referer=self.urlsearch))
            return html
        else:
            return None
            print "No results found"
    def download_malware(self,url):
        malware = self.client.get("https://malwr.com"+url,headers=dict(Referer=self.urlsearch))
        file_output = "malwr"+str(randint(2,1000))
        file_output = open(os.path.join(COLLECTOR_ROOT,'download',file_output), 'wb')
        file_output.write(malware.content)
        file_output.close()

"""auth = MalwrAuth()
auth.login(LOGIN,"user",'password')
html = auth.search("0e463582d03789ed6e79f31fd7a1abc4")
report = auth.find_report(html)
if report!=None:
    print report"""





