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

import os
import json
import logging

from flask import Flask, request, make_response

from keyrock_client import KeyrockClient, KeyrockError
from settings import IDM_HOST, IDM_PASSWD, IDM_USER, BROKER_APP_ID, BROKER_ROLES, \
     BAE_APP_ID, BAE_ROLES


app = Flask(__name__)

@app.route("/tenant", methods=['POST'])
def create():
    # Get tenant info for JSON request
    if 'tenant' not in request.json:
        return make_response(json.dumps({
            'error': 'Missing required field tenant'
        }), 422)

    if 'authorization' not in request.headers or \
            not request.headers.get('authorization').lower().startswith('bearer '):

        return make_response(json.dumps({
            'error': 'This request requires authentication'
        }), 401)

    keyrock_client = KeyrockClient(IDM_HOST, IDM_USER, IDM_PASSWD)

    # Authorize user making the request
    token = request.headers.get('authorization').split(' ')[1]

    try:
        user_info = keyrock_client.authorize(token)
    except:
        return make_response(json.dumps({
            'error': 'This request requires authentication'
        }), 401)

    try:
        org_id = keyrock_client.create_organization(
            request.json.get('tenant'), request.json.get('description'), user_info['id'])

        # Add context broker role
        keyrock_client.authorize_organization(org_id, BROKER_APP_ID, BROKER_ROLES)

        # Add BAE roles
        keyrock_client.authorize_organization(org_id, BAE_APP_ID, BAE_ROLES)

    except KeyrockError as e:
        return make_response(json.dumps({
            'error': str(e)
        }), 400)
    except Exception:
        return make_response(json.dumps({
            'error': 'Unexpected error creating tenant'
        }), 500)

    return make_response('', 201)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=(os.environ.get("DEBUG", "false").strip().lower() == "true"))
else:
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
