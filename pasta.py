#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# >>
#   Copyright 2018 Vivint, inc.
#
#    pasta, 2018
# <<

"""Pasta paste-bin service."""

import os
import json
import time
import string
import random
import base64
from hashlib import md5
from datetime import datetime
from logging import getLogger
from logging.config import fileConfig
from typing import Callable

from bottle import get, post, run, template, \
    redirect, abort, static_file, request


def env(v, default, as_: Callable=str):
    ret = os.getenv(v, None)
    return as_(default) if ret is None else as_(ret)


# ~~ constants
HOST= env('HOST', '0.0.0.0')
PORT = env('PORT', 8544, int)
DEBUG = env('DEBUG', 1, bool)

# ~~ setup
fileConfig('logging.ini')
logger = getLogger('')
outdir = os.path.join(os.getcwd(), 'data')
static_dir = os.path.join(os.getcwd(), 'static')
paste_cache = {}


# ~~ helpers
def gen_sha(length=8):
    return ''.join(
        random.choice(string.ascii_letters + string.digits)
        for _ in range(length))


def get_paste(sha):
    fullpath = os.path.join(outdir, f'{sha}.json')
    if os.path.exists(fullpath):
        with open(fullpath, 'r') as ins_file:
            data = json.load(ins_file)


        contents = data['contents'].encode('ascii')

        # verify the contents
        new_md5 = md5(contents).hexdigest()

        # verify the unencoded contents
        raw_contents = base64.b64decode(contents)
        raw_md5 = md5(raw_contents).hexdigest()

        data['contents'] = raw_contents
        data['meta']['verified'] = new_md5 == data['meta']['md5']
        data['meta']['md5_raw'] = raw_md5
        return data
    return None


def set_paste(sha, token, payload: dict):
    if paste_cache.get(sha, '') == token:
        fullpath = os.path.join(outdir, f'{sha}.json')
        with open(fullpath, 'w') as out_file:
            json.dump(payload, out_file, ensure_ascii=True, indent=4)
        return True
    return False


@get('/<sha>')
def index(sha):
    page_token = gen_sha(64)
    save_token = paste_cache.setdefault(sha, page_token)
    paste_data = get_paste(sha)
    timestamp = time.time()
    return template('index.html', **locals())


@post('/<sha>')
def do_index(sha):
    f = request.forms.get

    page_token = f('pageToken')
    encrypt = f('encryptBox') is not None
    contents = f('contentsField')

    contents = base64.b64encode(bytearray(contents, 'ascii'))
    md5sum = md5(contents).hexdigest()

    data = {
        'title': f('titleField'),
        'contents': contents.decode('ascii'),
        'created': float(f('timestamp')),
        'posted': time.time(),
        'meta': {
            'encrypted': encrypt,
            'md5': md5sum,
            'verified': None
        }
    }

    saved = set_paste(sha, page_token, data)

    if not saved:
        abort(403, 'Forbidden: you are not authorized to edit this paste')

    logger.info(f'saved -- {md5sum}')
    redirect(f'/{sha}')


@get('/')
def empty_index():
    sha = gen_sha()
    redirect(f'/{sha}')


@get('/static/css/<path:re:.*\.css>')
def css(path):
    return static_file(path, root=static_dir)


# ~~ serve forever
run(host=HOST, port=PORT, interval=3, reloader=DEBUG, debug=DEBUG)
