#-------------------------------------------------------------------------------
# Name:        ExampleClass
# Purpose:     Example Class
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
import sys,os
import logging

log = logging.getLogger()

class Example:
    def __init__(self):
        self.legend = "Example Class for Triana"
        self.genreport = dict()
    def run(self):
        log.info(self.legend)
        try:
            self.genreport["status"] = True
            self.genreport["example_malwarefound"] = "http://urlmalware.com"
            self.genreport["example_analysis"] = "FOO"
            self.genreport["example_peinfo"] = "BAR"
            return self.genreport
        except Exception as error:
            self.genreport["status"] = False
            log.error(error)
            return self.genreport
    def __del(self):
        pass
