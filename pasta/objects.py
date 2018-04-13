#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# >>
#   Copyright 2018 Vivint, inc.
#
#    pasta, 2018
# <<

import os
import uuid
from datetime import datetime, timedelta

from attr import attrs

from pasta.config import config

PASTE_DELIM = '__'
PASTE_SCHEMA = '{uuid}__{expires}'
uuid_limit = config.pasta.limit_uuid or 6


@attrs(auto_attribs=True)
class Paste(object):
    uuid:       str
    created:    datetime
    expires:    datetime
    path:       str

    @classmethod
    def from_path(cls, path):
        assert os.path.exists(path)
        created = os.stat(path).st_ctime
        uid, expires = path.split(PASTE_DELIM)
        if int(expires) == 0:
            expires = None
        else:
            expires = datetime.utcfromtimestamp(expires)
        created = datetime.utcfromtimestamp(created)
        return Paste(uid, created, expires, path)

    @classmethod
    def new(cls, contents, path=None, days=None):
        if path is None:
            path = os.getenv('PASTA_DATA', None)
        assert os.path.isdir(path)

        if days:
            expires = datetime.utcnow() + timedelta(days=days)
            expires_str = expires.timestamp()

        else:
            expires = None
            expires_str = '0'

        uid = uuid.uuid4().hex[:uuid_limit]
        name = PASTE_SCHEMA.format(uuid=uid, expires=expires_str)
        dest = os.path.join(path, name)
        with open(dest, 'w', encoding='utf-8') as out_file:
            out_file.write(contents)

        return Paste(
            uuid=uid, created=datetime.utcnow(), path=dest, expires=expires)
