#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# >>
#   Copyright 2018 Vivint, inc.
#
#    pasta, 2018
# <<

import os
from logging import getLogger

import falcon
from jinja2 import Environment, FileSystemLoader

from pasta.config import config
from pasta.handles.main import MainHandler

logger = getLogger(__name__)


def create_app():
    api = falcon.API()
    jinja = Environment(
        auto_reload=True,
        enable_async=True,
        loader=FileSystemLoader(**config.templates.loader))

    api.add_route('/', MainHandler(jinja))

    api.add_static_route('/static', os.path.abspath(config.static.path))

    return api


def get_app():
    return create_app()


api = get_app()


if __name__ == '__main__':
    from wsgiref import simple_server
    logger.warning('wsgi app is running standalone on dev server')
    httpd = simple_server.make_server('0.0.0.0', 8000, api)
    httpd.serve_forever()
