#-------------------------------------------------------------------------------
# Name:        Loader
# Purpose:     Main class. Loader all plugins
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
import inspect,sys,pkgutil
import plugins
import logging

try:
    log = logging.getLogger(__name__)
except:
    pass

def LoadPlugins():
    package=plugins
    obj = {}
    for importer, modname, ispkg in pkgutil.iter_modules(path=package.__path__,prefix=package.__name__+'.'):
        module = __import__(modname,locals(),[],-1)
        for name,cls in inspect.getmembers(module):
          if inspect.isclass(cls):
            obj[cls.__name__] =modname
    return obj

def LoadMethods(obj):
    task = dict()
    for name,cls in obj.iteritems():
        pack = sys.modules[cls]
        nabo = getattr(pack,name)
        paquete = nabo()
        try:
            data = paquete.run()
            task[name] = data
        except AttributeError:
            pass
    return task


def ListPlugins(obj):
    for name,cls in obj.iteritems():
        log.info("Plugin {0} loaded ".format(name))

