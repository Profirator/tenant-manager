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

from lib.keyrock_client import KeyrockClient, KeyrockError
from lib.umbrella_client import UmbrellaClient, UmbrellaError
from settings import IDM_HOST, IDM_PASSWD, IDM_USER, BROKER_APP_ID, BROKER_ROLES, \
     BAE_APP_ID, BAE_ROLES, BROKER_ADMIN_ROLE, BROKER_CONSUMER_ROLE, BAE_SELLER_ROLE, \
     BAE_CUSTOMER_ROLE, BAE_ADMIN_ROLE, UMBRELLA_HOST, UMBRELLA_TOKEN, UMBRELLA_KEY


app = Flask(__name__)


def _organization_based_tenant(keyrock_client, user_info):
    # This method seems not be usable due to the new Keyrock v7 implementation    
    org_id = keyrock_client.create_organization(
        request.json.get('tenant'), request.json.get('description'), user_info['id'])

    # Add context broker role
    keyrock_client.authorize_organization(org_id, BROKER_APP_ID, BROKER_ADMIN_ROLE, BROKER_CONSUMER_ROLE)

    # Add BAE roles
    keyrock_client.authorize_organization_role(org_id, BAE_APP_ID, BAE_SELLER_ROLE, 'owner')
    keyrock_client.authorize_organization_role(org_id, BAE_APP_ID, BAE_CUSTOMER_ROLE, 'owner')
    keyrock_client.authorize_organization_role(org_id, BAE_APP_ID, BAE_ADMIN_ROLE, 'owner')

def _app_based_tenant(keyrock_client, user_info):
    broker_app = keyrock_client.get_application(BROKER_APP_ID)

    # Create new application for the broker tenant
    app_id = keyrock_client.create_application(
        request.json.get('tenant'), request.json.get('description'),
        broker_app['application']['url'], broker_app['application']['redirect_uri'])

    # Create broker roles
    for role in BROKER_ROLES:
        keyrock_client.create_role(app_id, role)

    # Grant provider role to tenant owner
    keyrock_client.grant_application_role(app_id, user_info['id'], 'provider')


def _build_policy(method, tenant, role):
    return {
        "http_method": method,
        "regex": "^/",
        "settings": {
            "required_headers": [{
                "key": "Fiware-Service",
                "value": tenant
            }],
            "required_roles": [
                role
            ],
            "required_roles_override": True
        }
    }


def _create_access_policies(user_info):
    # Build read and admin policies
    tenant = request.json.get('tenant')

    read_role = tenant.lower().replace(' ', '-') + '.' + BROKER_CONSUMER_ROLE
    read_policy = _build_policy('get', tenant, read_role)

    admin_role = tenant.lower().replace(' ', '-') + '.' + BROKER_ADMIN_ROLE
    admin_policy = _build_policy('any', tenant, admin_role)

    # Add new policies to existing API sub settings
    umbrella_client = UmbrellaClient(UMBRELLA_HOST, UMBRELLA_TOKEN, UMBRELLA_KEY)
    umbrella_client.add_sub_url_setting_app_id(BROKER_APP_ID, [read_policy, admin_policy])


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
        #_app_based_tenant(keyrock_client, user_info)
        _organization_based_tenant(keyrock_client, user_info)
        _create_access_policies(user_info)
    except (KeyrockError, UmbrellaError) as e:
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
