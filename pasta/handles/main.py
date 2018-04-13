#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# >>
#   Copyright 2018 Vivint, inc.
#
#    pasta, 2018
# <<

import random
from logging import getLogger

import attr
import falcon
from falcon import Request as Req, Response as Resp

from pasta.objects import Paste


class MainHandler(object):
    def __init__(self, jinja):
        self.jinja = jinja
        self.logger = getLogger('app.MainHandler')

    def on_get(self, req: Req, resp: Resp):
        p = Paste.new(
            contents=str(random.randint(100, 1000)))

        data = {
            'paste': attr.asdict(p)
        }

        resp.body = self.jinja.get_template('index.html').render(**data)
        resp.content_type = falcon.MEDIA_HTML
