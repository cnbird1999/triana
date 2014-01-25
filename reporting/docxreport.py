#-------------------------------------------------------------------------------
# Name:        DOCXReport
# Purpose:     Generate Full DOCX Report.
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------

from util.docx import *
from lxml import *
from util.TableParse import parse,clean as limpia
import os
from common.constants import COLLECTOR_ROOT
from util.Info import *
import json

def make_word(md5hash,tmp,reputation,domreput,reportdir):
    relationships = relationshiplist()
    genreport = json.loads(tmp)
    doc = opendocx(os.path.join(COLLECTOR_ROOT,"util","doc.docx"))
    docbody = doc.xpath('/w:document/w:body',
    namespaces=nsprefixes)[0]
    advReplace(docbody,"Title",("Analysis for MD5 %s" %md5hash))
    docbody.append(heading('''File Information''',1) )
    docbody.append(paragraph(False))
    docbody.append(paragraph(File_Paragraph))
    docbody.append(paragraph(False))
    if genreport.__contains__("Malwr") or genreport["PandaSecurity"].__contains__("status")or genreport.__contains__("VirusTotal"):
        if genreport["PandaSecurity"].__contains__("status"):
            try:
                File_Information["MD5"] = genreport["PandaSecurity"]["details"]["MD5"]
                File_Information["SHA1"] = genreport["PandaSecurity"]["details"]["SHA-1"]
                File_Information["Filetype"] = genreport["PandaSecurity"]["details"]["File Type"]
                File_Information["Size"] = genreport["PandaSecurity"]["details"]["Size (bytes)"]
                #File_Information["Packer"] = genreport["Malwr"]["Packer"]
            except KeyError:
                log.info("No information data in Xandora...")
                pass
        if genreport.__contains__("VirusTotal"):
            try:
                File_Information["MD5"] = genreport["VirusTotal"]["md5"]
                File_Information["SHA1"] = genreport["VirusTotal"]["sha1"]
                File_Information["SHA256"] = genreport["VirusTotal"]["sha256"]
            except KeyError:
                log.info("No information data in VirusTotal...")
                pass
        if genreport["ShadowServer"].__contains__("status")==True:
            try:
                File_Information["MD5"] = genreport["ShadowServer"]["md5"]
                File_Information["SHA1"] = genreport["ShadowServer"]["sha1"]
                File_Information["Filetype"] = genreport["ShadowServer"]["filetype"]
                File_Information["First_seen"] = genreport["ShadowServer"]["First_seen"]
                File_Information["last_seen"] = genreport["ShadowServer"]["last_seen"]
            except KeyError as e:
                log.info("No information data in ShadowServer...")
                log.info(e)
                pass
        if genreport.__contains__("Malwr"):
            try:
                File_Information["FileName"] = genreport["Malwr"]["details"]["File Name"]
                File_Information["MD5"] = genreport["Malwr"]["details"]["MD5"]
                File_Information["SHA1"] = genreport["Malwr"]["details"]["SHA1"]
                File_Information["Filetype"] = genreport["Malwr"]["details"]["File Type"]
                File_Information["Size"] = genreport["Malwr"]["details"]["File Size"]
                File_Information["SHA256"] = genreport["Malwr"]["details"]["SHA256"]
                File_Information["ssdeep"] = genreport["Malwr"]["details"]["Ssdeep"]
                File_Information["CRC32"] = genreport["Malwr"]["details"]["CRC32"]
            except KeyError as e:
                log.info("No information data in Malwr...")
                log.info(e)
                pass
            except Exception as e:
                log.error(e)
                pass

    #Insert Data
    #print File_Information
    docbody.append(table([['MD5',File_Information["MD5"]],
                          ['SHA1',File_Information["SHA1"]],
                          ['First_seen',File_Information["First"]],
                          ['last_seen',File_Information["Last"]],
                          ['Filetype',File_Information["Filetype"]],
                          ['Size',File_Information["Size"]],
                          ['Ssdeep',File_Information["ssdeep"]]],heading = False))
    #Section Graph
    docbody.append(paragraph(False))
    docbody.append(heading('''Graph With data founded''',1) )
    docbody.append(paragraph(False))
    for root,dirs,files in os.walk(os.path.join(COLLECTOR_ROOT,"charts"),topdown=True):
            if not files:
                break
            os.chdir("charts")
            for f in range(0,len(files)):
                try:
                    if files[f]=="GraphData.png":
                        relationships,picpara = picture(relationships,
                                                        files[f],'Graph generated')
                        docbody.append(picpara)
                        docbody.append(paragraph(False))
                except IOError as e:
                    log.error(e)
                    pass
    os.chdir(COLLECTOR_ROOT)
    #Section Analysis
    docbody.append(paragraph(False))
    docbody.append(heading('''Analysys Information''',1) )
    docbody.append(paragraph(False))
    docbody.append(paragraph(Analysis_Information))
    docbody.append(paragraph(False))
    try:
        if genreport["VirusTotal"]["results"]!=False:
            docbody.append(heading('''Antivirus detection at Virustotal''',2) )
            docbody.append(paragraph(False))
            docbody.append(paragraph(VirusTotal_info))
            os.chdir("charts")
            relationships,picpara = picture(relationships,'VirusTotal.png','VirusTotal Graphics detection')
            docbody.append(picpara)
            docbody.append(paragraph(False))
            os.chdir(COLLECTOR_ROOT)
    except:
        pass
    #Section Files created
    if genreport["PandaSecurity"].__contains__("changes") or genreport["Malwr"].__contains__("dropped_files"):
        docbody.append(pagebreak(type='page', orient='portrait'))
        docbody.append(heading('''Files changes''',2) )
        docbody.append(paragraph(False))
        docbody.append(paragraph(Files_Paragraph))
        try:
            if genreport["PandaSecurity"].__contains__("changes"):
                docbody.append(table(genreport["PandaSecurity"]["changes"]))
                docbody.append(paragraph(False))
        except:
            pass
        try:
            if genreport["Malwr"].__contains__("dropped_files"):
                docbody.append(heading('''Dropped Files''',2))
                docbody.append(paragraph(False))
                for item in genreport["Malwr"]["dropped_files"]:
                    for key,value in item.items():
                        docbody.append(paragraph(key+":"+value,style='ListBullet'))
                    docbody.append(paragraph(False))
        except KeyError:
            pass
    if domreput:
        try:
            docbody.append(heading('''Domain Reputation''',1) )
            docbody.append(paragraph(False))
            for d,rep,status in domreput:
                if status["status"] ==True:
                    docbody.append(heading('''Reputation for Domain {0}'''.format(d),2) )
                    docbody.append(paragraph(False))
                    if os.path.isfile(os.path.join(COLLECTOR_ROOT,"charts","{0}.png".format(d))):
                        try:
                            os.chdir('charts')
                            relationships,picpara = picture(relationships,"{0}.png".format(d),'Domain Reputation')
                            docbody.append(picpara)
                            docbody.append(paragraph(False))
                            os.chdir(COLLECTOR_ROOT)
                        except:
                            #docbody.append(paragraph(paratext =[("No graphics detected....",'b')]))
                            pass
                    replist = list()
                    replist.append(("Reputation List","Status"))
                    for key,value in rep.items():
                        replist.append((key,str(value)))
                    docbody.append(table(replist, heading=True))
                else:
                    docbody.append(heading('''Reputation for Domain {0}'''.format(d),2) )
                    docbody.append(paragraph(paratext =[("No graphics detected....",'b')]))
                    docbody.append(paragraph(False))
        except Exception as e:
            log.error(e)
    if reputation:
        try:
            docbody.append(heading('''IP Reputation''',1) )
            docbody.append(paragraph(False))
            for ip,rep,status in reputation:
                if status["status"] == True:
                    docbody.append(heading('''Reputation for IP {0}'''.format(ip),2) )
                    docbody.append(paragraph(False))
                    if os.path.isfile(os.path.join(COLLECTOR_ROOT,"charts","{0}.png".format(ip))):
                        try:
                            os.chdir('charts')
                            relationships,picpara = picture(relationships,"{0}.png".format(ip),'IP Reputation')
                            docbody.append(picpara)
                            docbody.append(paragraph(False))
                            os.chdir(COLLECTOR_ROOT)
                        except:
                            #docbody.append(paragraph(paratext =[("No graphics detected....",'b')]))
                            pass
                    replist = list()
                    replist.append(("Reputation List","Status"))
                    for key,value in rep.items():
                        replist.append((key,str(value)))
                    docbody.append(table(replist, heading=True))
                else:
                    docbody.append(heading('''Reputation for IP {0}'''.format(ip),2) )
                    docbody.append(paragraph(paratext =[("No graphics detected....",'b')]))
                    docbody.append(paragraph(False))

        except Exception as e:
            log.error(e)
    try:
        if genreport["VirusTotal"]["results"]!=False:
            docbody.append(heading('''Annex VirusTotal''',1) )
            docbody.append(paragraph(False))
            docbody.append(table(genreport["VirusTotal"]["results"]))
            docbody.append(paragraph(False))
    except KeyError:
        pass
    #Anex Panda Security
    if genreport["PandaSecurity"]["status"]==True:
        docbody.append(paragraph(False))
        docbody.append(heading('''Annex Xandora''',1))
        docbody.append(paragraph(False))
        try:
            if genreport["PandaSecurity"].__contains__("details"):
                docbody.append(heading('''File Details''',2))
                docbody.append(paragraph(False))
                docbody.append(paragraph(paratext =[('Malware Name: '),(genreport["PandaSecurity"]["malware_name"],'b')],style='ListBullet'))
                for key,value in genreport["PandaSecurity"]["details"].items():
                    docbody.append(paragraph(key+":"+value,style='ListBullet'))
                docbody.append(paragraph(False))
        except KeyError:
            pass
        try:
            if genreport["PandaSecurity"].__contains__("headers"):
                docbody.append(heading('''Headers Found''',2))
                docbody.append(paragraph(False))
                docbody.append(paragraph(str(genreport["PandaSecurity"]["headers"])))
        except KeyError:
            pass
        try:
            if genreport["PandaSecurity"].__contains__("Process"):
                docbody.append(heading('''Process Details''',2))
                docbody.append(paragraph(False))
                docbody.append(table(genreport["PandaSecurity"]["Process"]))
                docbody.append(paragraph(False))
        except KeyError:
            pass
        try:
            if genreport["PandaSecurity"].__contains__("changes"):
                docbody.append(heading('''Change Details''',2))
                docbody.append(paragraph(False))
                docbody.append(table(genreport["PandaSecurity"]["changes"]))
                docbody.append(paragraph(False))
        except KeyError:
            pass
        try:
            if genreport["PandaSecurity"].__contains__("Registry_changes"):
                docbody.append(heading('''Registry Changes''',2))
                docbody.append(paragraph(False))
                docbody.append(table(genreport["PandaSecurity"]["Registry_changes"]))
                docbody.append(paragraph(False))
        except KeyError:
            pass
    #Anex ThreatExpert
    if genreport["ThreatExpert"]["status"] == True:
        docbody.append(heading('''Annex ThreatExpert''',1) )
        docbody.append(paragraph(False))
        try:
            if genreport["ThreatExpert"].__contains__("sample_info"):
                docbody.append(heading('''File Details''',2))
                docbody.append(paragraph(False))
                for key,value in genreport["ThreatExpert"]["sample_info"].items():
                    docbody.append(paragraph(key+":"+str(value),style='ListBullet'))
                docbody.append(paragraph(False))
        except KeyError as e:
            log.error(e)
        docbody.append(paragraph(False))
        docbody.append(heading('''What's been found''',2))
        docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("flags"):
            for entry in genreport["ThreatExpert"]["flags"]:
                for key,value in entry.items():
                    docbody.append(paragraph(value,style='ListBullet'))
                    docbody.append(paragraph('Severity Level: '+key,style='ListBullet'))
        docbody.append(paragraph(False))
        docbody.append(heading('''Technical details''',2))
        docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("Threat"):
            docbody.append(paragraph(False))
            docbody.append(paragraph(genreport["ThreatExpert"]["Threat"]))
            docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("know_threat"):
            for threat in genreport["ThreatExpert"]["know_threat"]:
                for key,value in threat.items():
                    docbody.append(paragraph(key+":"+str(value),style='ListBullet'))
            docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("added_files"):
            docbody.append(heading('''Files Added''',2))
            docbody.append(paragraph(False))
            docbody.append(table(genreport["ThreatExpert"]["added_files"]))
            docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("added_modules"):
            docbody.append(heading('''Module Loaded''',2))
            docbody.append(paragraph(False))
            docbody.append(paragraph('The following modules were loaded into the address space of other process(es):'))
            docbody.append(paragraph(False))
            docbody.append(table(genreport["ThreatExpert"]["added_modules"]))
            docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("added_regkeys"):
            docbody.append(heading('''Reg Keys added''',2))
            docbody.append(paragraph('The following Registry Keys were created:'))
            docbody.append(paragraph(False))
            for regadd in genreport["ThreatExpert"]["added_regkeys"]:
                docbody.append(paragraph(paratext =[regadd,'b'],style='ListBullet'))
            docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("reg_structure"):
            docbody.append(paragraph(False))
            docbody.append(paragraph('The newly created Registry Values are:'))
            docbody.append(paragraph(False))
            docbody.append(table(genreport["ThreatExpert"]["reg_structure"]))
            docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("mutexes"):
            docbody.append(heading('''Mutex added''',2))
            docbody.append(paragraph('The following Mutex were created:'))
            docbody.append(paragraph(False))
            for mutex in genreport["ThreatExpert"]["mutexes"]:
                docbody.append(paragraph(paratext =[mutex,'b'],style='ListBullet'))
            docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("host_file"):
            docbody.append(heading('''Host File modified''',2))
            docbody.append(paragraph('The HOSTS file was updated with the following URL-to-IP mappings:'))
            docbody.append(paragraph(False))
            for hostfile in genreport["ThreatExpert"]["host_file"]:
                docbody.append(paragraph(hostfile,style='ListBullet'))
            docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("countries"):
            docbody.append(paragraph
            ('Analysis of the file resources indicate the following possible country of origin: {0}'.format(
            genreport["ThreatExpert"]["countries"][0])))
        docbody.append(paragraph(False))
        docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("ipconnect"):
            docbody.append(heading('''Remote Connections''',2))
            docbody.append(paragraph(False))
            docbody.append(paragraph('There was registered attempt to establish connection with the remote host. The connection details are:'))
            docbody.append(paragraph(False))
            docbody.append(table(genreport["ThreatExpert"]["ipconnect"]))
            docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("download_files"):
            docbody.append(heading('''Remote URL Connections''',2))
            docbody.append(paragraph(False))
            docbody.append(paragraph('The data identified by the following URL was then requested from the remote web server.'))
            docbody.append(paragraph(False))
            for host in genreport["ThreatExpert"]["download_files"]:
                docbody.append(paragraph(host,style='ListBullet'))
            docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("internet_connect"):
            docbody.append(paragraph('The following Internet Connection was established:'))
            docbody.append(paragraph(False))
            docbody.append(table(genreport["ThreatExpert"]["internet_connect"]))
            docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("outbound_traffic"):
            docbody.append(paragraph('There was an outbound traffic produced on port {0}'.format(genreport["ThreatExpert"]["port_connection"])))
            docbody.append(paragraph(False))
            for outbound in genreport["ThreatExpert"]["outbound_traffic"]:
                docbody.append(paragraph(outbound))
            docbody.append(paragraph(False))
        if genreport["ThreatExpert"].__contains__("url_download"):
            docbody.append(heading('''Download Files''',2))
            docbody.append(paragraph('The following Internet download was started (the retrieved bits are saved into the local file):'))
            docbody.append(paragraph(False))
            for host,filename in genreport["ThreatExpert"]["url_download"]:
                docbody.append(paragraph("Url to Download: {0}".format(host),style='ListBullet'))
                docbody.append(paragraph("Filename: {0}".format(filename),style='ListBullet'))





    #Anex CleanMX
    if genreport["CleanMX"]["status"] == True:
        docbody.append(heading('''Annex CleanMX''',1) )
        docbody.append(paragraph(False))
        docbody.append(table(genreport["CleanMX"]["cleanmx"]))
        docbody.append(paragraph(False))
    #Anex Malc0de
    if genreport["Malc0de"]["status"] == True:
        docbody.append(heading('''Annex Malc0de''',1) )
        docbody.append(paragraph(False))
        docbody.append(table(genreport["Malc0de"]["malicious"]))
        docbody.append(paragraph(False))
    #Anex Malekal
    if genreport["Malekal"]["status"] == True:
        try:
            docbody.append(paragraph(False))
            docbody.append(heading('''Annex Malekal''',1) )
            docbody.append(paragraph(False))
            docbody.append(paragraph(paratext =[('Sha1: '),(genreport["Malekal"]["sha1"],'b')],style='ListBullet'))
            docbody.append(paragraph(paratext =[('md5: '),(genreport["Malekal"]["md5"],'b')],style='ListBullet'))
            docbody.append(paragraph(paratext =[('Date: '),(genreport["Malekal"]["date"],'b')],style='ListBullet'))
            docbody.append(paragraph(paratext =[('Size: '),(genreport["Malekal"]["size"],'b')],style='ListBullet'))
            docbody.append(paragraph(paratext =[('File Detection: '),(genreport["Malekal"]["FileDetection"],'b')],style='ListBullet'))
        except KeyError as e:
            log.error(e)
            pass
    #Anex Malwr
    if genreport["Malwr"].__contains__("status"):
        docbody.append(paragraph(False))
        docbody.append(heading('''Annex Malwr''',1))
        docbody.append(paragraph(False))
        try:
            if genreport.get("Malwr")["details"]:
                docbody.append(heading('''File Details''',2))
                docbody.append(paragraph(False))
                for key,value in genreport["Malwr"]["details"].items():
                    docbody.append(paragraph(key+":"+value,style='ListBullet'))
                docbody.append(paragraph(False))
        except KeyError:
            pass
        if genreport["Malwr"].__contains__("files"):
            docbody.append(heading('''Files''',2))
            docbody.append(paragraph(False))
            for files in genreport["Malwr"]["files"]:
                docbody.append(paragraph(paratext =[(files,'b')],style='ListBullet'))
            docbody.append(paragraph(False))
        if genreport["Malwr"].__contains__("regkeys"):
            docbody.append(heading('''Registry Keys''',2))
            docbody.append(paragraph(False))
            for regkey in genreport["Malwr"]["regkeys"]:
                docbody.append(paragraph(paratext =[(regkey,'b')],style='ListBullet'))
            docbody.append(paragraph(False))
        if genreport["Malwr"].__contains__("mutexes"):
            docbody.append(heading('''Mutex''',2))
            docbody.append(paragraph(False))
            for mutex in genreport["Malwr"]["mutexes"]:
                docbody.append(paragraph(paratext =[(mutex,'b')],style='ListBullet'))
            docbody.append(paragraph(False))

        if genreport["Malwr"].__contains__("pe_resources") or genreport["Malwr"].__contains__("pe_imports") or genreport["Malwr"].__contains__("pe_sections"):
            docbody.append(heading('''Static Analysis''',2))
            docbody.append(paragraph(False))
            try:
                if genreport["Malwr"].__contains__("signatures"):
                    docbody.append(paragraph(paratext =[("Signature Match",'b')]))
                    docbody.append(paragraph(False))
                    for signature in genreport["Malwr"]["signatures"]:
                        docbody.append(paragraph(paratext =[(signature,'b')],style='ListBullet'))
                    docbody.append(paragraph(False))
            except KeyError:
                pass
            try:
                if genreport["Malwr"].__contains__("versioninfo"):
                    docbody.append(paragraph(paratext =[("PE Version Info",'b')]))
                    for key,value in genreport["Malwr"]["versioninfo"].items():
                        docbody.append(paragraph(key+":"+value,style='ListBullet'))
                docbody.append(paragraph(False))
            except KeyError:
                pass
            try:
                if genreport["Malwr"].__contains__("pe_sections"):
                    docbody.append(paragraph(paratext =[("PE Sections",'b')]))
                    docbody.append(table(genreport["Malwr"]["pe_sections"]))
                docbody.append(paragraph(False))
            except KeyError:
                pass
            try:
                if genreport["Malwr"].__contains__("pe_imports"):
                    docbody.append(paragraph(paratext =[("PE Imports",'b')]))
                    for i in genreport["Malwr"]["pe_imports"]:
                        if len(i)>10:
                            docbody.append(table(i[:10],heading=True))
                            docbody.append(paragraph(False))
                        else:
                            docbody.append(table(i,heading=True))
                            docbody.append(paragraph(False))
                docbody.append(paragraph(False))
            except KeyError:
                pass
            if genreport["Malwr"].__contains__("dropped_files"):
                docbody.append(heading('''Dropped Files''',2))
                docbody.append(paragraph(False))
                for item in genreport["Malwr"]["dropped_files"]:
                    for key,value in item.items():
                        docbody.append(paragraph(key+":"+value,style='ListBullet'))
                    docbody.append(paragraph(False))
            try:
                if genreport["Malwr"].__contains__("behavior"):
                    docbody.append(heading('''Behavior''',2))
                    docbody.append(paragraph(False))
                    for behavior in genreport["Malwr"]["behavior"]:
                        tmplist = list()
                        tmplist.append(("Category","TimeStamp","API"))
                        docbody.append(paragraph(paratext =[("Behavior for the file {0}".format(behavior["process_name"]),'b')]))
                        docbody.append(paragraph(False))
                        datos =  behavior["calls"][:10]
                        for value in datos:
                            tmplist.append((value["category"],value["timestamp"],value["api"]))
                        docbody.append(table(tmplist,heading=True))
                        docbody.append(paragraph(False))
            except KeyError:
                pass
            ####Network Info########
            if genreport["Malwr"].__contains__("dns_requests") or genreport["Malwr"].__contains__("http_requests"):
                docbody.append(paragraph(False))
                docbody.append(heading('''Network Analysis''',2))
                docbody.append(paragraph(False))
                try:
                    if genreport["Malwr"].__contains__("network_signatures"):
                        docbody.append(heading('''Network Summary''',3) )
                        docbody.append(paragraph(False))
                        for signature in genreport["Malwr"]["network_signatures"]:
                            docbody.append(paragraph(paratext =[(signature,'b')],style='ListBullet'))
                        docbody.append(paragraph(False))
                except KeyError:
                    pass
                try:
                    if genreport["Malwr"].__contains__("dns_requests"):
                        docbody.append(heading('''DNS Queries''',3) )
                        docbody.append(paragraph(False))
                        docbody.append(table(genreport["Malwr"]["dns_requests"],heading=True))
                    docbody.append(paragraph(False))
                except KeyError:
                    pass
                try:
                    if genreport["Malwr"].__contains__("http_requests"):
                        docbody.append(heading('''HTTP Queries''',3) )
                        docbody.append(paragraph(False))
                        docbody.append(table(genreport["Malwr"]["http_requests"],heading=True))
                        docbody.append(paragraph(False))
                except KeyError:
                    pass
    #Add Images
    if genreport["Malwr"].__contains__("images") or \
       genreport["ThreatExpert"].__contains__("screen") or \
       genreport["Sarvam"].__contains__("image"):
        for root,dirs,files in os.walk(os.path.join(COLLECTOR_ROOT,"tmp"),topdown=True):
            if not files:
                break
            os.chdir("tmp")
            docbody.append(paragraph(False))
            docbody.append(heading('''Images''',1))
            docbody.append(paragraph(False))
            for f in range(0,len(files)):
                try:
                    if files[f] == "threatexpert.gif":
                        relationships,picpara = picture(relationships,
                                                        files[f],'Image Extracted from ThreatExpert.com')
                        docbody.append(heading("Screenshot from ThreatExpert.com",2) )
                        docbody.append(picpara)
                        docbody.append(paragraph(False))
                    elif files[f] == "sarvam.png":
                        relationships,picpara = picture(relationships,
                                                        files[f],'Image Extracted from sarvam.ece.ucsb.edu',
                                                        pixelwidth=450,pixelheight=400)
                        docbody.append(heading("Screenshot from sarvam.ece.ucsb.edu",2) )
                        docbody.append(picpara)
                        docbody.append(paragraph(False))
                    elif files[f] == "worldmap.png":
                        relationships,picpara = picture(relationships,
                                                        files[f],'Image Extracted from Google Maps',
                                                        pixelwidth=450,pixelheight=400)
                        docbody.append(heading("Screenshot IP Location from Google Maps",2) )
                        docbody.append(picpara)
                        docbody.append(paragraph(False))
                    else:
                        relationships,picpara = picture(relationships,
                                                        files[f],'Image Extracted from malwr.com',
                                                        pixelwidth=450,pixelheight=400)
                        docbody.append(heading("Screenshot from Malwr.com",2) )
                        docbody.append(picpara)
                        docbody.append(paragraph(False))
                except IOError as e:
                    log.error(e)
                    pass
            os.chdir(COLLECTOR_ROOT)

    #Adding doc or pdf
    if genreport["MalwareTrackerDoc"]["status"] == True or genreport["MalwareTrackerPdf"]["status"] == True :
        docbody.append(heading('''Annex Malwaretracker''',1) )
        docbody.append(paragraph(False))
        if genreport["MalwareTrackerDoc"]["status"] == True:
            docbody.append(heading('''Information for DOC Found''',2) )
            docbody.append(paragraph(False))
            for key,value in genreport["MalwareTrackerDoc"]["report"].items():
                if value:
                    docbody.append(paragraph(key+": "+value,style='ListBullet'))
            docbody.append(paragraph(False))
            docbody.append(paragraph( \
                           paratext =[("RAW Strings: {0}".format( \
                           "http://www.malwaretracker.com/docstrings.php?md5={0}".format(genreport["MalwareTrackerDoc"] \
                           ["report"]["md5"])),'b')]))
            docbody.append(paragraph(False))
            docbody.append(paragraph( \
                           paratext =[("Decrypted RAW Strings: {0}".format( \
                           "http://www.malwaretracker.com/docstrings.php?md5={0}&subfile=0".format(genreport["MalwareTrackerDoc"] \
                           ["report"]["md5"])),'b')]))
            docbody.append(paragraph(False))
            docbody.append(paragraph( \
                           paratext =[("URL: {0}".format( \
                           "http://www.malwaretracker.com/docsearch.php?hash={0}".format(genreport["MalwareTrackerDoc"] \
                           ["report"]["md5"])),'b')]))
        if genreport["MalwareTrackerPdf"]["status"] == True:
            if genreport["MalwareTrackerPdf"].__contains__("filename"):
                docbody.append(heading('''Basic information for PDF found''',2) )
                docbody.append(paragraph(False))
                docbody.append(paragraph( \
                                         paratext =[("Filename: {0}".format( \
                                         genreport["MalwareTrackerPdf"]["filename"]),'b')]))
            if genreport["MalwareTrackerPdf"].__contains__("submitted"):
                docbody.append(paragraph( \
                                         paratext =[("Submitted: {0}".format( \
                                         genreport["MalwareTrackerPdf"]["submitted"]),'b')]))
            if genreport["MalwareTrackerPdf"].__contains__("size"):
                docbody.append(paragraph( \
                                         paratext =[("Size: {0}".format( \
                                         genreport["MalwareTrackerPdf"]["size"]),'b')]))
            if genreport["MalwareTrackerPdf"].__contains__("md5"):
                docbody.append(paragraph( \
                                         paratext =[("MD5: {0}".format( \
                                         genreport["MalwareTrackerPdf"]["md5"]),'b')]))
            if genreport["MalwareTrackerPdf"].__contains__("sha1"):
                docbody.append(paragraph( \
                                         paratext =[("Sha1: {0}".format( \
                                         genreport["MalwareTrackerPdf"]["sha1"]),'b')]))
            if genreport["MalwareTrackerPdf"].__contains__("sha256"):
                docbody.append(paragraph( \
                                         paratext =[("Sha256: {0}".format( \
                                         genreport["MalwareTrackerPdf"]["sha256"]),'b')]))
            if genreport["MalwareTrackerPdf"].__contains__("ssdeep"):
                docbody.append(paragraph( \
                                         paratext =[("ssdeep: {0}".format( \
                                         genreport["MalwareTrackerPdf"]["ssdeep"]),'b')]))
            if genreport["MalwareTrackerPdf"].__contains__("severity"):
                docbody.append(paragraph( \
                                         paratext =[("Severity: {0}".format( \
                                         genreport["MalwareTrackerPdf"]["severity"]),'b')]))
            if genreport["MalwareTrackerPdf"].__contains__("encrypted"):
                if genreport["MalwareTrackerPdf"]["encrypted"] == "0":
                    docbody.append(paragraph(paratext =[("The PDF file is not encrypted"),"b"]))
                else:
                    docbody.append(paragraph(paratext =[("The PDF file is encrypted"),"b"]))
            if genreport["MalwareTrackerPdf"].__contains__("exploits"):
                docbody.append(heading('''Exploits used in PDF file''',2) )
                docbody.append(paragraph(False))
                for exploit in genreport["MalwareTrackerPdf"]["exploits"]:
                    docbody.append(paragraph(paratext =[(exploit,"b")],style='ListBullet'))
            docbody.append(heading('''Online information for PDF file''',2) )
            docbody.append(paragraph(False))
            docbody.append(paragraph( \
                           paratext =[("URL: {0}".format( \
                           "https://www.malwaretracker.com/pdfdata.php?md5={0}&type=document".format(genreport["MalwareTrackerPdf"] \
                           ["md5"])),'b')]))


        docbody.append(paragraph(False))

    #Add information Whois
    ###Append Whois information###
    if genreport.__contains__("WhoisDomain"):
        docbody.append(heading('''Annex Whois Information for Domain address''',1) )
        docbody.append(paragraph(False))
        for key,value in genreport["WhoisDomain"].items():
            if not "Error" in value:
                try:
                    d = "Whois information for domain %s" %key
                    docbody.append(heading(d,2) )
                    docbody.append(paragraph(False))
                    dat = value.split("\n")
                    for n in dat:
                        docbody.append(paragraph(n))
                except:
                    pass
            else:
                try:
                    for key,value in genreport["WhoisDomain"].items():
                        d = "Whois information for domain %s" %key
                        docbody.append(heading(d,2) )
                        for e,m in value.items():
                            docbody.append(paragraph(paratext =[e+" ",
                                                 (m,'b')],style='ListBullet'))
                    docbody.append(paragraph(False))
                except Exception as e:
                    log.error(e)
                    pass


    ###Append Whois IP###
    if genreport.__contains__("WhoisIP"):
        docbody.append(heading('''Annex Whois Information for IP Address''',1) )
        docbody.append(paragraph(False))
        for ip,data in genreport["WhoisIP"].items():
            if not "Error" in data:
                try:
                    message = "Whois for IP Address %s" %data["DomainName"]
                    docbody.append(heading(message,2) )
                    docbody.append(paragraph(False))
                    docbody.append(paragraph(paratext =[('IP Address: '),
                                             (data["DomainName"],'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('Update Date: '),
                                             (data["RegistryData"]["UpdatedDate"],
                                             'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('Create Date: '),
                                             (data["RegistryData"]["UpdatedDate"],
                                             'b')],style='ListBullet'))

                    docbody.append(paragraph(paratext =[("Abuse Contact","iu")]))

                    docbody.append(paragraph(paratext =[('Phone: '),
                                             (data["RegistryData"]["AbuseContact"]["Phone"],
                                             'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('Email: '),
                                             (data["RegistryData"]["AbuseContact"]["Email"],
                                             'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('Name: '),
                                             (data["RegistryData"]["AbuseContact"]["Name"],
                                             'b')],style='ListBullet'))


                    docbody.append(paragraph(paratext =[("Administrative Contact","iu")]))

                    docbody.append(paragraph(paratext =[('Phone: '),
                                             (data["RegistryData"]["AdministrativeContact"]["Phone"],
                                             'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('Email: '),
                                             (data["RegistryData"]["AdministrativeContact"]["Email"],
                                             'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('Name: '),
                                             (data["RegistryData"]["AdministrativeContact"]["Name"],
                                             'b')],style='ListBullet'))

                    docbody.append(paragraph(paratext =[("Technical Contact","iu")]))

                    docbody.append(paragraph(paratext =[('Phone: '),
                                             (data["RegistryData"]["TechnicalContact"]["Phone"],
                                             'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('Email: '),
                                             (data["RegistryData"]["TechnicalContact"]["Email"],
                                             'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('Name: '),
                                             (data["RegistryData"]["TechnicalContact"]["Name"],
                                             'b')],style='ListBullet'))

                    docbody.append(paragraph(paratext =[("About Registrant","iu")]))

                    docbody.append(paragraph(paratext =[('City: '),
                                             (data["RegistryData"]["Registrant"]["City"],
                                             'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('Name: '),
                                             (data["RegistryData"]["Registrant"]["Name"],
                                             'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('State: '),
                                             (data["RegistryData"]["Registrant"]["StateProv"],
                                             'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('City: '),
                                             (data["RegistryData"]["Registrant"]["City"],
                                             'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('Country: '),
                                             (data["RegistryData"]["Registrant"]["Country"],
                                             'b')],style='ListBullet'))
                    docbody.append(paragraph(paratext =[('Address: '),
                                             (data["RegistryData"]["Registrant"]["Address"],
                                             'b')],style='ListBullet'))

                    docbody.append(paragraph(paratext =[('Postal Code: '),
                                             (data["RegistryData"]["Registrant"]["PostalCode"],
                                             'b')],style='ListBullet'))
                except KeyError as e:
                    log.error(e)
                    pass
                except Exception as e:
                    log.error(e)
                    pass




    ###Generate DocX ###
    coreprops = coreproperties(title='TRIANA',subject='Malware Analysis Tool',
                               creator='TRIANA',keywords=['TRIANA',
                               'Office Open XML','Word','Malware'])
    appprops = appproperties()
    content_types = contenttypes()
    web_settings = websettings()
    word_relationships = wordrelationships(relationships)

    savedocx(doc,coreprops, appprops, content_types, web_settings,
             word_relationships, os.path.join(COLLECTOR_ROOT,
             "reports",reportdir,"Report",("TechnicalReport%s.docx") %md5hash))
