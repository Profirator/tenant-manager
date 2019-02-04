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
