#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      silverhack
#
# Created:     17/07/2013
# Copyright:   (c) silverhack 2013
# Licence:     <your licence>
#-------------------------------------------------------------------------------
#http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
import pygeoip
import requests
import os
from common.constants import COLLECTOR_ROOT
import logging

log = logging.getLogger()

_MAPSTR = "&markers=color:%s|%.6f,%.6f"
_MAPURLBASE = "http://maps.google.com/maps/api/staticmap?zoom=1&size=500x300&sensor=false"

class Geo:
    def __init__(self,ipaddress=False):
        self.ipaddress = ipaddress

    def getUrl(self,mapbase=_MAPURLBASE):
        maps = []
        colors = ['red', 'yellow']
        try:
            gic = pygeoip.GeoIP(os.path.join(COLLECTOR_ROOT,"geo",'GeoLiteCity.dat'), pygeoip.MEMORY_CACHE)
            for ip,rep,status in self.ipaddress:
                if status["status"] == True:
                    coloridx = 0
                else:
                    coloridx = 1
                data = gic.record_by_addr(ip)
                maps += [_MAPSTR % (colors[coloridx],
                                        data['latitude'],
                                        data['longitude'])
                         ]
            url = mapbase + "".join(maps)
            FinalMap = requests.get(url)
            out = open(os.path.join(COLLECTOR_ROOT,"tmp","worldmap.png"),"wb")
            out.write(FinalMap.content)
            out.close()
        except Exception as error:
            log.error(error)

"""def main():
    url = getUrl(ipaddress)
    print url
    pass

if __name__ == '__main__':
    main()"""
