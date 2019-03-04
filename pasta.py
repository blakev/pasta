#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# >>
#   pasta, 2019
# <<

import io
import gc
import os
import json
import string
import random
from time import monotonic as time_fn
from datetime import datetime
from logging import getLogger
from logging.config import fileConfig
from hashlib import md5, sha1
from collections import namedtuple

import toml
from easydict import EasyDict
from toolz.functoolz import curry
from cryptography.fernet import Fernet, MultiFernet
from flask import \
    Flask, Response, abort, make_response, render_template, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Length

from typing import List, Union


# ~~ load the configuration
config_path = os.path.abspath(os.getenv('PASTA_CONFIG_PATH', './config.toml'))
with open(config_path, 'r') as fp:
    config = EasyDict(toml.load(fp))
logging_path = os.getenv('PASTA_LOGGING_CONFIG', config.logging_path)
fileConfig(logging_path)
logger = getLogger('pasta')
app_log = getLogger('pasta.app').info
DATA_DIR = os.getenv('PASTA_DATA_PATH', config.data_folder)
ENCODING = config.encoding
STARTED = datetime.utcnow(), time_fn()

logger.info('started_at: %s, %0.1f', *STARTED)
logger.info('config: %s', config_path)
logger.info('logging: %s', logging_path)
logger.info('data: %s', DATA_DIR)
logger.info('encoding: %s', ENCODING)

# ~~~~~~ ENCRYPTION
key_path = os.path.join(DATA_DIR, '.keys')

# delete stale keys if forced
if config.get('force_keygen', False):
    if os.path.exists(key_path):
        os.unlink(key_path)

# generate new keys if the keygen file does not exist
if not os.path.isfile(key_path):
    count = int(config.keygen_keycount)
    logger.info('generating %d keys', count)
    with open(key_path, 'wb') as fp:
        for _ in range(count):
            fp.write(Fernet.generate_key() + b'\n')

# always load in new keys whether they were generated or stored
with open(key_path, 'rb') as fp:
    keys = list(map(bytes.strip, fp))

enc = MultiFernet([Fernet(key) for key in keys])


# ~~~~~~ HASHING
@curry
def _hash(fn, buffer: Union[io.StringIO, io.BytesIO]):
    """Partial function for generating checksum of binary content."""

    buffer.seek(0)
    hashsum = fn()
    for chunk in iter(lambda: buffer.read(4096), b''):
        hashsum.update(chunk)
    return hashsum.hexdigest()


@curry
def _s_hash(fn, data: str):
    """Partial function for generating checksum of string content."""

    return fn(_b(data)).hexdigest()


@curry
def gen_sha(charset: List[str], length: int):
    """Partial function for generating a long string of random characters."""

    def inner() -> str:
        return ''.join(random.choice(charset) for _ in range(length))
    return inner


def safe_uuid() -> str:
    """Ensure our UUID is unique to the /data directory for storing info."""

    taken = os.listdir(DATA_DIR)
    while True:
        new_uuid = gen_uuid()
        if new_uuid in taken:
            logger.warning('uuid collision %s', new_uuid)
        else:
            logger.info('uuid=%s', new_uuid)
            return new_uuid


uuid_chars = set(string.ascii_letters + string.digits)
uuid_chars.difference_update(*config.uuids_do_not_include)

md5sum = _hash(md5)
sha1sum = _hash(sha1)
md5sum_str = _s_hash(md5)
sha1sum_str = _s_hash(sha1)
gen_uuid = gen_sha(list(uuid_chars), max(4, int(config.uuids_size)))
gen_token = gen_sha(string.ascii_letters + string.digits, config.token_size)


# ~~~~~~ DATA HANDLING

DataObj = namedtuple('DataObj', 'title contents uuid sha1 md5')


def _b(v: str) -> bytes:
    return bytes(v, encoding=ENCODING)


def _s(v: bytes) -> str:
    return v.decode(ENCODING) if isinstance(v, bytes) else str(v)


def save_data(data: DataObj):
    """Save posted data to the filesystem after encrypting."""

    filename = os.path.join(DATA_DIR, data.uuid)
    contents = {k: _s(v) for k, v in data._asdict().items()}
    contents = json.dumps(contents, ensure_ascii=False, sort_keys=True, indent=2)

    logger.info('writing %s', filename)
    with open(filename, 'wb') as fp:
        fp.write(_b(contents))

    del contents
    del data
    gc.collect(1)


def remove_data(uuid: str) -> None:
    """Removes the pasted data file from disk."""

    filename = os.path.join(DATA_DIR, uuid)
    if os.path.exists(filename):
        logger.info('removed %s', filename)
        os.unlink(filename)
    else:
        logger.warning('%s does not exist to remove', filename)


def load_data(uuid: str) -> Union[int, 'DataObj']:
    """Attempts to load, and validate, the encrypted data stored on disk."""

    filename = os.path.join(DATA_DIR, uuid)

    if not os.path.exists(filename):
        return 404  # does not exist

    logger.info('reading %s', filename)

    try:
        with open(filename, 'rb') as fp:
            contents = fp.read()
        contents = json.loads(_s(contents))
        buff = _b(contents.get('contents', ''))
        # validate contents against checksums
        buff = io.BytesIO(buff)

        if contents['sha1'] == sha1sum(buff) and \
            contents['md5'] == md5sum(buff):

                buff.seek(0)
                contents['contents'] = data = _s(enc.decrypt(buff.read()))
                contents['md5'] = md5sum_str(data)
                contents['sha1'] = sha1sum_str(data)
        else:
            logger.warning('cannot validate file contents')
            return 403
    except Exception as e:
        logger.error(e)
        return 500

    # success!
    return DataObj(**contents)


# ~~~~~~ WEBSITE
class PasteForm(FlaskForm):
    title = StringField(
        'Title',
        validators=[
            DataRequired(),
            Length(min=1, max=255)
        ])
    content = TextAreaField(
        'Content',
        validators=[
            DataRequired(),
            Length(min=1, max=config.pastes.max_size)
        ])
    token = HiddenField('token')

    def to_meta(self, uuid: str):
        data = enc.encrypt(self.content.data.encode(ENCODING))
        buff = io.BytesIO(data)
        meta = DataObj(
            title=self.title.data,
            contents=data,
            uuid=uuid,
            sha1=sha1sum(buff),
            md5=md5sum(buff))
        return meta


def make_app() -> Flask:
    """Create a Flask application container."""
    logger.info('creating flask application')
    app = Flask(
        'pasta',
        static_url_path='/static',
        static_folder='./static',
        template_folder='./views')
    config.flask.SECRET_KEY = os.urandom(32)
    config.flask.SERVER_NAME = None
    app.config.from_mapping(config.flask)
    return app


app = make_app()
uuid_table = {}


@app.route('/', methods=['GET'])
def index():
    uuid = safe_uuid()
    token = gen_token()
    form = PasteForm(token=token)
    resp = make_response(
        render_template(
            'index.html',
            uuid=uuid,
            token=token,
            form=form,
            editable=True
    ))
    uuid_table[uuid] = token
    app_log('tracking key %s=%s', uuid, token)
    return resp


@app.route('/<uuid>/raw', methods=['GET'])
def handle_raw_paste(uuid):
    data = load_data(uuid)
    if isinstance(data, int):
        abort(data)
    resp: Response = make_response(data.contents)
    resp.headers['Content-Type'] = 'text/plain'
    return resp


@app.route('/<uuid>/<token>/del', methods=['GET'])
def handle_delete_paste(uuid, token):
    if uuid_table.get(uuid, '') == token:
        app_log('removing paste %s', uuid)
        remove_data(uuid)
        uuid_table.pop(uuid)
    return redirect(url_for('index'))


@app.route('/<uuid>', methods=['GET', 'POST'])
def handle_paste(uuid):
    if request.method == 'POST':
        form = PasteForm()
        if form.validate_on_submit() and uuid_table.get(uuid, '') == form.token.data:
            save_data(form.to_meta(uuid))
            return redirect(url_for('handle_paste', uuid=uuid))
        else:
            app_log('%s', form.errors.items())
        # invalid form
        app_log('invalid form data')
        abort(403)
    # if request is GET
    data = load_data(uuid)
    if isinstance(data, int):  # error code
        abort(data)
    size = len(data.contents)
    token = uuid_table.pop(uuid, '')
    can_delete = bool(token)
    return render_template(
        'index.html', can_delete=can_delete, data=data, size=size,
        token=token, uuid=uuid, editable=False)


if __name__ == '__main__':
    app.run('0.0.0.0', 8000, True)
