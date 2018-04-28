#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# >>
#   Copyright 2018 Vivint, inc.
#
#    pasta, 2018
# <<

"""Pasta paste-bin service application."""

import os
import json
import string
import random
from queue import Queue
from logging import getLogger, LoggerAdapter
from logging.config import fileConfig

import attr
import dill
import toml
from attr import attrs, attrib
from flask import Flask, Response, abort, redirect, request, render_template, \
    send_from_directory, url_for
from easydict import EasyDict
from redis import StrictRedis
from redis.exceptions import RedisError
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Length
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA1, MD5

# ~~ setup
CONFIG_FILE = os.getenv('PASTA_CONFIG_FILE', 'flask.toml')
fileConfig('logging.ini')
logger = getLogger(__name__)
config = EasyDict(**toml.load(open(CONFIG_FILE, 'r')))
redis = StrictRedis(**config.redis)
data_folder = config.data_folder
ENCODING = config.encoding

# ~~ setup encryption
logger.info('initializing encryption')
secret = config.encryption.secret
secret = get_random_bytes(32) if not secret else bytes(secret, ENCODING)[:32]


# ~~ fn
def _b(v):
    return bytes(v, encoding=ENCODING)

def _s(v):
    return v.decode(ENCODING)


@attrs(frozen=True, slots=True)
class MetaData(object):
    sha = attrib(type=str)
    title = attrib(type=str)
    content = attrib(type=str)


@attrs(frozen=True, slots=True)
class EncryptedData(object):
    msg = attrib(type=str)
    sha1 = attrib(type=str)
    md5 = attrib(type=str)

    def hash_short(self, length=4):
        return '%s:%s' % (self.md5[:length], self.sha1[:length])

    @property
    def nonce(self):
        return self.msg[:8]

    @property
    def ciphertext(self):
        return self.msg[8:]


EmptyEncData = EncryptedData(None, None, None)


class EncryptionAdapter(LoggerAdapter):
    def process(self, msg, kwargs):
        context = kwargs.pop('ctx', EmptyEncData)  # type: EncryptedData
        assert isinstance(context, EncryptedData)
        return '[%s] %s' % (context.hash_short(), msg), kwargs


enc_logger = EncryptionAdapter(logger, extra={})


def gen_sha(charset, length=8):
    def inner():
        return ''.join(random.choice(charset) for _ in range(length))
    return inner


uuid_chars = set(string.ascii_letters + string.digits)
uuid_chars.difference_update(*config.uuids_do_not_include)
new_uuid = gen_sha(list(uuid_chars), config.uuids_size)
new_token = gen_sha(string.ascii_letters + string.digits, 128)


def short_codes():
    que = Queue(maxsize=config.uuids_pregen)
    while True:
        disk_codes = os.listdir(data_folder)
        for x in range(config.uuids_pregen):
            v = new_uuid()
            if v not in disk_codes:
                que.put_nowait(v)

        if que.empty():
            raise RuntimeError("depleted gen'd uuid keys, increase `pregen`")

        while not que.empty():
            yield que.get_nowait()


uuids = short_codes()


# ~~ encryption

def hash_data(data):
    hmac_sha = HMAC.new(secret, digestmod=SHA1)
    hmac_md5 = HMAC.new(secret, digestmod=MD5)
    hmac_sha.update(data)
    hmac_md5.update(data)
    return hmac_sha, hmac_md5


def encrypt(data, nonce=None):
    if not isinstance(data, (bytes, bytearray)):
        data = bytearray(data, encoding=ENCODING)

    if nonce is None:
        nonce = get_random_bytes(8)

    logger.debug('encrypting %d bytes of data', len(data))

    cipher = Salsa20.new(key=secret, nonce=nonce)
    msg = _s(cipher.nonce + cipher.encrypt(data))
    sha, md5 = hash_data(data)

    data = EncryptedData(
        msg=msg,
        sha1=sha.hexdigest(),
        md5=md5.hexdigest())

    enc_logger.debug('success', ctx=data)
    return data


def decrypt(data: EncryptedData):
    enc_logger.debug(
        'decrypting %d bytes of data', len(data.msg), ctx=data)
    cipher = Salsa20.new(key=secret, nonce=_b(data.nonce))
    plaintext = cipher.decrypt(_b(data.ciphertext))
    sha, md5 = hash_data(plaintext)

    expected = data.sha1, data.md5
    actual = sha.hexdigest(), md5.hexdigest()

    if expected != actual:
        enc_logger.error(
            'data integrity error, expected %s calculated %s',
            data.md5, md5.hexdigest(), ctx=data)
        raise ValueError('hash value of contents does not match')
    enc_logger.debug('decrypted data verified', ctx=data)
    return plaintext


# ~~ web/db

class PasteForm(FlaskForm):
    title = StringField(
        'title', validators=[DataRequired()])
    content = TextAreaField(
        'contents', validators=[DataRequired(), Length(min=1, max=config.pastes.max_size)])
    token = HiddenField('token')

    def to_meta_obj(self, sha):
        meta = MetaData(
            sha=sha,
            title=self.title.data,
            content=self.content.data)
        return meta


def save_incoming_data(meta: MetaData):
    filename = os.path.join(data_folder, meta.sha)
    # encrypt and update
    data = encrypt(json.dumps(attr.asdict(meta)))
    # perform the save
    with open(filename, 'wb') as out_file:
        contents = json.dumps(
            attr.asdict(data), ensure_ascii=False, sort_keys=False, indent=0)
        out_file.write(_b(contents))
    logger.debug('saved %s', filename)
    # destroy plaintext data
    del meta


def load_outgoing_data(sha: str):
    if sha not in os.listdir(data_folder):
        abort(404)
    filename = os.path.join(data_folder, sha)
    with open(filename, 'rb') as ins_file:
        contents = ins_file.read().decode(ENCODING)
        data = json.loads(contents)
    logger.debug('loaded %s', filename)
    enc_data = EncryptedData(**data)
    try:
        data = decrypt(enc_data)
    except ValueError as e:
        enc_logger.error('data integrity error %s', sha, ctx=enc_data)
        abort(422)  # unprocessable entity
    data = json.loads(_s(data))
    meta = MetaData(**data)
    enc_logger.debug('processed successfully', ctx=enc_data)
    return meta


def check_redis(do_raise=False):
    logger.info('check redis connection')
    try:
        redis.info()
    except RedisError as e:
        logger.error(e)
        if do_raise:
            raise e
        return False
    return True


def make_app():
    """Create a flask application for WSGI hosting."""
    logger.info('create flask application')
    app = Flask(__name__,
                static_url_path='/static',
                static_folder='./static',
                template_folder='./views')
    app.config.from_mapping(config.flask)
    check_redis(do_raise=True)
    return app


app = make_app()


@app.route('/', methods=['GET'])
def index():
    token = new_token()
    uuid = new_uuid()
    form = PasteForm(token=token)
    redis.setex(uuid, config.pastes.uuid_expires_in, token)
    return render_template('index.html', **locals())


@app.route('/<sha>', methods=['GET'])
def view_paste(sha):
    meta = load_outgoing_data(sha)
    return Response(meta.content, 200, mimetype='text/plain')


@app.route('/<sha>', methods=['POST'])
def do_paste(sha):
    form = PasteForm()
    if form.validate_on_submit():
        db_key = (redis.get(sha) or b'').decode(ENCODING)
        if db_key != form.token.data:
            logger.warning('invalid edit token during submission')
            abort(403)
        save_incoming_data(form.to_meta_obj(sha))
        return redirect(url_for('view_paste', sha=sha))
    abort(403)


@app.route('/static/<path:path>')
def send_static_content(path):
    return send_from_directory('static', path)


if __name__ == '__main__':
    app.run('localhost', 8544, True)
