#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Opplafy Tenant Manager
# Copyright (C) 2019  Future Internet Consulting and Development Solutions S.L.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import json

from flask import request, make_response
import mimeparse

from lib.keyrock_client import KeyrockClient, KeyrockError
from settings import IDM_URL, IDM_PASSWD, IDM_USER


def build_response(body, status):
    resp = make_response(json.dumps(body), status)
    resp.headers['Content-Type'] = 'application/json'
    return resp


def authorized(funct):
    def wrapper(*args, **kwargs):
        if 'authorization' not in request.headers or \
                not request.headers.get('authorization').lower().startswith('bearer '):

            return build_response({
                'error': 'This request requires authentication'
            }, 401)

        keyrock_client = KeyrockClient(IDM_URL, IDM_USER, IDM_PASSWD)

        # Authorize user making the request
        token = request.headers.get('authorization').split(' ')[1]

        try:
            user_info = keyrock_client.authorize(token)
        except KeyrockError:
            return build_response({
                'error': 'This request requires authentication'
            }, 401)

        arguments = (user_info,) + args
        return funct(*arguments, **kwargs)

    # Renaming the function name to prevent Flask crashing
    wrapper.__name__ = funct.__name__
    return wrapper


def get_content_type(request):
    content_type_header = request.headers.get('content-type')
    if content_type_header is not None:
        try:
            type, subtype, params = mimeparse.parse_mime_type(content_type_header)
            return type + "/" + subtype
        except mimeparse.MimeTypeParseException:
            pass

    return ''


def consumes(mime_types):

    if type(mime_types) == str:
        mime_types = (mime_types,)

    def wrap(func):
        def wrapper(*args, **kwargs):
            if get_content_type(request) not in mime_types:
                return build_response({
                    'error': 'Unsupported request media type'
                }, 415)

            return func(*args, **kwargs)
        # Renaming the function name to prevent Flask crashing
        wrapper.__name__ = func.__name__
        return wrapper

    return wrap
