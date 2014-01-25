#-------------------------------------------------------------------------------
# Name:        Utils
# Purpose:     Utils from TRIANA
# Author:      Juan Garrido (A.K.A silverhack)
# Created:     22/04/2013
# Copyright (C) 2013 Threat Intelligent Analysis.
# This file is part of TRIANA http://www.innotecsystem.com
# See the file 'docs/LICENSE' for copying permission.
#-------------------------------------------------------------------------------
import os
import sys
import string
import shutil
import logging
import hashlib
import json

log = logging.getLogger(__name__)

def create_folders(root =".",folders=[]):
    for folder in folders:
        if os.path.exists(os.path.join(root, folder)):
            continue
        else:
            create_folder(root, folder)


def create_folder(root=".", folder=None):
    if not os.path.exists(os.path.join(root, folder)) and folder:
        try:
            folder_path = os.path.join(root, folder)
            os.makedirs(folder_path)
        except OSError as e:
            raise

def delete_tmp(root=".", folders=None):
    for folder in folders:
        if os.path.exists(os.path.join(root, folder)):
            log.info("Deleting temporary folder %s" %folder)
            path = os.path.join(root,folder)
            shutil.rmtree(path)

def delete_media(root="."):
    for root,dirs,files in os.walk(os.path.join(root,"util","template","word","media"),topdown=True):
        for f in files:
            path = os.path.join(root,f)
            os.remove(path)


def HashingMalware(muestra):
    try:
        md5=open(muestra,'rb').read()
        md5_new=hashlib.md5(md5).hexdigest()
        return(md5_new)
    except IOError as e:
        print "The file could not be found..."
        sys.exit()

def convert_json(data):
    """Converts data dict to json
    """
    #response.content_type = "application/json; charset=UTF-8"
    return json.dumps(data, sort_keys=False, indent=4)
