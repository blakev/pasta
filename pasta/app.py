#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# >>
#   Copyright 2018 Vivint, inc.
#
#    pasta, 2018
# <<

from logging import getLogger

import falcon

logger = getLogger(__name__)


def create_app():
    api = falcon.API()
    return api


def get_app():
    return create_app()


api = get_app()


if __name__ == '__main__':
    from wsgiref import simple_server
    logger.warning('wsgi app is running standalone on dev server')
    httpd = simple_server.make_server('0.0.0.0', 5000, api)
    httpd.serve_forever()
