#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# >>
#   Copyright 2018 Vivint, inc.
#
#    pasta, 2018
# <<

import os

import toml
from easydict import EasyDict

DEFAULT_CONFIG = os.getenv('PASTA_CONFIG', './pasta.config.toml')


def get_config(path: str) -> EasyDict:
    path = os.path.abspath(path)
    with open(path, 'r') as ins_file:
        conf = toml.load(ins_file)
    return EasyDict(conf)


config = get_config(DEFAULT_CONFIG)
