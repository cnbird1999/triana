#-------------------------------------------------------------------------------
# Name:        module2
# Purpose:
#
# Author:      silverhack
#
# Created:     02/07/2013
# Copyright:   (c) silverhack 2013
# Licence:     <your licence>
#-------------------------------------------------------------------------------
from util.startup import Triana,init_logging,Create_Structure
from common.config import ConfigFile
from common.constants import COLLECTOR_ROOT
from util.utils import *
from reporting.docxreport import make_word
import win32com.client
import sys
import hashlib
options = dict()
proclist = list()
md5proclist = list()
md5list= list()
wmi=win32com.client.GetObject('winmgmts:')

folders2 = ["blacklist",
               "charts",
               "malware",
               "tmp"]

class _options:
    def __init__(self):
        self.json = True
        self.docx = True
        self.reputation = False
        self.logging = "info"

def HashingMalware(muestra):
    try:
        md5=open(muestra,'rb').read()
        md5_new=hashlib.md5(md5).hexdigest()
        return(md5_new)
    except IOError as e:
        #print "The file could not be found..."
        return None
        #sys.exit()

def ListProcess():
    for p in wmi.InstancesOf('win32_process'):
        proclist.append((p.Name,int(p.Properties_('ProcessId')),str(p.Properties_('ExecutablePath'))))
        children=wmi.ExecQuery('Select * from win32_process where ParentProcessId=%s' %p.Properties_('ProcessId'))
        for child in children:
            proclist.append((child.Name,int(child.Properties_('ProcessId')),str(child.Properties_('ExecutablePath'))))

ListProcess()
for name,pid,path in proclist:
    md5 = HashingMalware(path)
    if md5 is not None:
        md5proclist.append((name,pid,path,md5))

for name,pid,path,md5 in md5proclist:
    md5list.append(md5)


options = _options()
md5list = sorted(list(set(md5list)))
init_logging("info")
for md5 in md5list:
    delete_tmp(root = COLLECTOR_ROOT, folders = folders2)
    delete_media(root= COLLECTOR_ROOT)
    Create_Structure()
    print "Checking MD5:%s" %md5
    Triana(md5,options)






