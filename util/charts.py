#-------------------------------------------------------------------------------
# Name:        Charts
# Purpose:     Main class for generate Charts
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
import os
from common.constants import COLLECTOR_ROOT
import cairoplot
import cairo
import logging
import json

try:
    log = logging.getLogger(__name__)
except:
    pass

class Charts:
    def __init__(self,tmp,ips=False,domains=False):
        self.genreport = json.loads(tmp)
        self.ips = ips
        self.domains = domains

    def PlotVirusTotal(self):
        ####New Graphics######
        if self.genreport["VirusTotal"]["results"]!=False:
            NoDetected = int(self.genreport["VirusTotal"]["total_av"]) - int(self.genreport["VirusTotal"]["positives"])
            data = {"No detected" : int(NoDetected), "Detected" : int(self.genreport["VirusTotal"]["positives"])}
            background = cairo.LinearGradient(300, 0, 300, 400)
            #background.add_color_stop_rgb(0,0,0.4,0)
            #background.add_color_stop_rgb(1.0,0,0.1,0)
            colors = [ (73.0/255, 233.0/255, 163.0/255),
                       (1.0,0.0,0.0),
                       (195.0/255, 255.0/255, 140.0/255),
                       (5.0/255, 3.0/255, 3.0/255),
                       (2.0/255, 255.0/255, 1.0/255) ]
            cairoplot.donut_plot(os.path.join(COLLECTOR_ROOT,"charts","VirusTotal.png"), data, 470, 170,
                                  background = background, gradient = True,
                                  shadow = True, colors = colors, inner_radius = 0.3)


    def PlotIPReputation(self):
        tempTable = {}
        for ip,rep,status in self.ips:
            if status["detected"] >0:
                log.info("the IP %s is detected in %i list and no detected in %i" %(ip,status["detected"],status["nodetected"]))
                data = {"No detected" : int(status["nodetected"]), "Detected" : int(status["detected"])}
                background = cairo.LinearGradient(300, 0, 300, 400)
                #background.add_color_stop_rgb(0,0,0.4,0)
                #background.add_color_stop_rgb(1.0,0,0.1,0)
                colors = [ (73.0/255, 233.0/255, 163.0/255),
                           (1.0,0.0,0.0),
                           (195.0/255, 255.0/255, 140.0/255),
                           (5.0/255, 3.0/255, 3.0/255),
                           (2.0/255, 255.0/255, 1.0/255) ]
                cairoplot.donut_plot(os.path.join(COLLECTOR_ROOT,"charts","{0}.png".format(ip)), data, 470, 170,
                                      background = background, gradient = True,
                                      shadow = True, colors = colors, inner_radius = 0.3)



    def GraphData(self):
        data = []
        virustotal = 0
        Malc0de = 0
        Malwaretracker = 0
        CleanMX = 0
        Reputation = 0
        ShadowServer = 0
        if self.genreport.__contains__("ThreatExpert"):
            data.append(self.genreport["ThreatExpert"]["count"])
        if self.genreport.__contains__("VirusTotal"):
            data.append(10)
        if self.genreport.__contains__("Malc0de"):
            data.append(self.genreport["Malc0de"]["count"])
        if self.genreport.__contains__("Malwr"):
            data.append(self.genreport["Malwr"]["count"])
        if self.genreport.__contains__("MalwareTrackerDoc"):
            data.append(self.genreport["MalwareTrackerDoc"]["count"])
        if self.genreport.__contains__("CleanMX"):
            data.append(self.genreport["CleanMX"]["count"])
        if self.genreport.__contains__("PandaSecurity"):
            data.append(self.genreport["PandaSecurity"]["count"])
        if self.genreport.__contains__("ShadowServer"):
            data.append(self.genreport["ShadowServer"]["count"])
        if self.genreport.__contains__("Malekal"):
            data.append(self.genreport["Malekal"]["count"])
        if self.genreport.__contains__("Sarvam"):
            data.append(self.genreport["Sarvam"]["count"])
        if self.genreport.__contains__("MalwareTrackerPdf"):
            data.append(self.genreport["MalwareTrackerPdf"]["count"])

        #y_labels = [ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10" ]
        x_labels = [ "ThreatExpert","VirusTotal","Malc0de","Malwr",
                     "MalwaretrackerDoc","Clean","Xandora","ShadowServer",
                     "Malekal","Sarvam","MalwareTrackerPdf"]
        cairoplot.vertical_bar_plot (os.path.join(COLLECTOR_ROOT,"charts","GraphData.png"), data, 700, 190, border = 20,
                                      display_values = True, grid = True, x_labels = x_labels,
                                      colors ="red_green_blue" )



    def PlotDomReputation(self):
        tempTable = {}
        for dom,rep, status in self.domains:
            if status["detected"] >0:
                log.info("the Domain %s is detected in %i list and no detected in %i" %(dom,status["detected"],status["nodetected"]))
                data = {"No detected" : int(status["nodetected"]), "Detected" : int(status["detected"])}
                background = cairo.LinearGradient(300, 0, 300, 400)
                #background.add_color_stop_rgb(0,0,0.4,0)
                #background.add_color_stop_rgb(1.0,0,0.1,0)
                colors = [ (73.0/255, 233.0/255, 163.0/255),
                           (1.0,0.0,0.0),
                           (195.0/255, 255.0/255, 140.0/255),
                           (5.0/255, 3.0/255, 3.0/255),
                           (2.0/255, 255.0/255, 1.0/255) ]
                cairoplot.donut_plot(os.path.join(COLLECTOR_ROOT,"charts","{0}.png".format(dom)), data, 470, 170,
                                      background = background, gradient = True,
                                      shadow = True, colors = colors, inner_radius = 0.3)


    def __del__(self):
        pass
