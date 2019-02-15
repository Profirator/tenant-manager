#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Opplafy Tenant Manager
# Copyright (C) 2019 Future Internet Consulting and Development Solutions S.L.

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
import logging
from copy import deepcopy

from flask import Flask, request, make_response
import mimeparse

from lib.database import DatabaseController
from lib.keyrock_client import KeyrockClient, KeyrockError
from lib.umbrella_client import UmbrellaClient, UmbrellaError
from lib.utils import authorized, build_response, consumes
from settings import (IDM_URL, IDM_PASSWD, IDM_USER, BROKER_APP_ID,
                      BAE_APP_ID, BROKER_ADMIN_ROLE, BROKER_CONSUMER_ROLE, BAE_SELLER_ROLE,
                      BAE_CUSTOMER_ROLE, BAE_ADMIN_ROLE, UMBRELLA_URL, UMBRELLA_TOKEN, UMBRELLA_KEY,
                      MONGO_HOST, MONGO_PORT)


app = Flask(__name__)


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


def _create_access_policies(tenant, org_id, user_info):
    # Build read and admin policies
    read_role = org_id + '.' + BROKER_CONSUMER_ROLE
    read_policy = _build_policy('GET', tenant, read_role)

    admin_role = org_id + '.' + BROKER_ADMIN_ROLE
    admin_policy = _build_policy('any', tenant, admin_role)

    # Add new policies to existing API sub settings
    umbrella_client = UmbrellaClient(UMBRELLA_URL, UMBRELLA_TOKEN, UMBRELLA_KEY)
    umbrella_client.add_sub_url_setting_app_id(BROKER_APP_ID, [read_policy, admin_policy])


def _map_roles(member):
    roles = [BROKER_CONSUMER_ROLE]

    if member['role'] == 'owner':
        roles.append(BROKER_ADMIN_ROLE)

    return roles


@app.route("/tenant", methods=['POST'])
@authorized
@consumes("application/json")
def create(user_info):
    # Get tenant info for JSON request
    if 'name' not in request.json:
        return build_response({
            'error': 'Missing required field name'
        }, 422)

    if 'description' not in request.json:
        return build_response({
            'error': 'Missing required field description'
        }, 422)

    if 'users' in request.json:
        for user in request.json.get('users'):
            if 'name' not in user or 'roles' not in user:
                return build_response({
                    'error': 'Missing required field in user specification'
                }, 422)

    tenant_id = None
    try:
        # Build tenant-id
        tenant_id = request.json.get('name').lower().replace(' ', '_')
        database_controller = DatabaseController(host=MONGO_HOST, port=MONGO_PORT)
        prev_t = database_controller.get_tenant(tenant_id)

        if prev_t is not None:
            return build_response({
                'error': 'The tenant {} is already registered'.format(tenant_id)
            }, 409)

        keyrock_client = KeyrockClient(IDM_URL, IDM_USER, IDM_PASSWD)
        org_id = keyrock_client.create_organization(
            request.json.get('name'), request.json.get('description'), user_info['id'])

        # Add context broker role
        keyrock_client.authorize_organization(org_id, BROKER_APP_ID, BROKER_ADMIN_ROLE, BROKER_CONSUMER_ROLE)

        # Add BAE roles
        keyrock_client.authorize_organization_role(org_id, BAE_APP_ID, BAE_SELLER_ROLE, 'owner')
        keyrock_client.authorize_organization_role(org_id, BAE_APP_ID, BAE_CUSTOMER_ROLE, 'owner')
        keyrock_client.authorize_organization_role(org_id, BAE_APP_ID, BAE_ADMIN_ROLE, 'owner')

        # Add tenant users if provided
        users = []
        for user in request.json.get('users', []):
            # User names are not used to identify users in Keyrock
            if 'id' not in user:
                user_id = keyrock_client.get_user_id(user['name'])
            else:
                user_id = user['id']

            user_obj = {
                'id': user_id,
                'name': user['name'],
                'roles': []
            }

            # Keyrock IDM only supports a single organization role
            if BROKER_CONSUMER_ROLE in user['roles'] and BROKER_ADMIN_ROLE not in user['roles']:
                keyrock_client.grant_organization_role(org_id, user_id, 'member')
                user_obj['roles'].append(BROKER_CONSUMER_ROLE)

            if BROKER_ADMIN_ROLE in user['roles']:
                keyrock_client.grant_organization_role(org_id, user_id, 'owner')
                user_obj['roles'].append(BROKER_ADMIN_ROLE)

            users.append(user_obj)

        _create_access_policies(tenant_id, org_id, user_info)
        database_controller.save_tenant(
            tenant_id, request.json.get('name'), request.json.get('description'), user_info['id'], users, org_id)

    except (KeyrockError, UmbrellaError) as e:
        return build_response({
            'error': str(e)
        }, 503)

    response = make_response('', 201)
    response.headers['Location'] = request.path + '/' + tenant_id

    return response


@app.route("/tenant", methods=['GET'])
@authorized
def get(user_info):
    response_data = []

    database_controller = DatabaseController(host=MONGO_HOST, port=MONGO_PORT)
    response_data = database_controller.read_tenants(user_info['id'])

    return build_response(response_data, 200)


@app.route("/tenant/<tenant_id>", methods=['GET'])
@authorized
def get_tenant(user_info, tenant_id):
    tenant_info = None
    try:
        database_controller = DatabaseController(host=MONGO_HOST, port=MONGO_PORT)
        tenant_info = database_controller.get_tenant(tenant_id)

        if tenant_info is None:
            return build_response({
                'error': 'Tenant {} does not exist'.format(tenant_id)
            }, 404)

        if tenant_info['owner_id'] != user_info['id']:
            return build_response({
                'error': 'You are not authorized to retrieve tenant info'
            }, 403)

        # Get tenant members from the IDM to keep the list
        # of members syncronized
        keyrock_client = KeyrockClient(IDM_URL, IDM_USER, IDM_PASSWD)
        members = keyrock_client.get_organization_members(tenant_info['tenant_organization'])
        tenant_info['users'] = [{
            'id': member['user_id'],
            'name': member['name'],
            'roles': _map_roles(member)
        } for member in members]

        database_controller.update_tenant(tenant_info)
    except KeyrockError:
        return build_response({
            'error': 'An error occurred reading tenants'
        }, 500)

    return build_response(tenant_info, 200)


def is_tenant_setting(setting, tenant_id):
    is_tenant = False

    if 'settings' in setting and 'required_headers' in setting['settings']:
        for header in setting['settings']['required_headers']:
            if header['key'].lower() == 'fiware-service' and header['value'] == tenant_id:
                is_tenant = True
                break

    return is_tenant


@app.route("/tenant/<tenant_id>/", methods=['DELETE'])
@authorized
def delete_tenant(user_info, tenant_id):
    try:
        database_controller = DatabaseController(host=MONGO_HOST, port=MONGO_PORT)
        tenant_info = database_controller.get_tenant(tenant_id)

        if tenant_info is None:
            return build_response({
                'error': 'Tenant {} does not exist'.format(tenant_id)
            }, 404)

        if tenant_info['owner_id'] != user_info['id']:
            return build_response({
                'error': 'You are not authorized to delete tenant'
            }, 403)

        # Delete organization in the IDM
        keyrock_client = KeyrockClient(IDM_URL, IDM_USER, IDM_PASSWD)
        keyrock_client.delete_organization(tenant_info['tenant_organization'])

        # Delete policies in API Umbrella
        umbrella_client = UmbrellaClient(UMBRELLA_URL, UMBRELLA_TOKEN, UMBRELLA_KEY)
        broker_api = umbrella_client.get_api_from_app_id(BROKER_APP_ID)

        sub_settings = [setting for setting in broker_api['sub_settings']
                        if not is_tenant_setting(setting, tenant_id)]

        broker_api['sub_settings'] = sub_settings
        umbrella_client.update_api(broker_api)

        # Delete tenant from database
        database_controller.delete_tenant(tenant_id)
    except (KeyrockError, UmbrellaError) as e:
        return build_response({
            'error': str(e)
        }, 400)

    return make_response('', 204)


def update_tenant_description(keyrock_client, tenant_info, tenant_update, patch):
    if 'value' not in patch:
        raise ValueError('Missing value field in JSON Patch replace operation')

    # Update organization description in IDM
    keyrock_client.update_organization(tenant_info['tenant_organization'], patch['value'])
    tenant_update['description'] = patch['value']


def add_tenant_user(keyrock_client, tenant_info, tenant_update, patch):
    if 'value' not in patch:
        raise ValueError('Missing value field in JSON Patch add operation')

    user = patch['value']
    if 'name' not in user or 'roles' not in user:
        raise ValueError('Invalid user info in JSON Patch')

    if 'id' not in user:
        user_id = keyrock_client.get_user_id(user['name'])
    else:
        user_id = user['id']

    # Check if the user is aleady included
    for prev_user in tenant_update['users']:
        if prev_user['id'] == user_id:
            raise ValueError('The user specified in JSON Patch is already included')

    user_obj = {
        'id': user_id,
        'name': user['name'],
        'roles': []
    }

    # Add the user as member of the organization
    if BROKER_CONSUMER_ROLE in user['roles'] and BROKER_ADMIN_ROLE not in user['roles']:
        keyrock_client.grant_organization_role(tenant_info['tenant_organization'], user_id, 'member')
        user_obj['roles'].append(BROKER_CONSUMER_ROLE)

    if BROKER_ADMIN_ROLE in user['roles']:
        keyrock_client.grant_organization_role(tenant_info['tenant_organization'], user_id, 'owner')
        user_obj['roles'].append(BROKER_ADMIN_ROLE)

    tenant_update['users'].append(user_obj)


def remove_tenant_user(keyrock_client, tenant_info, tenant_update, patch):
    # Get index of the user to be removed
    path = patch['path'].split('/')

    if len(path) != 3 or not path[2].isdigit():
        raise ValueError('Invalid format in path element of remove operation')

    index = int(path[2])

    # Check that the index point to a valid user
    if index >= len(tenant_info['users']):
        raise ValueError('Index out of range in remove operation')

    user = tenant_info['users'][index]

    if BROKER_ADMIN_ROLE in user['roles']:
        keyrock_client.revoke_organization_role(tenant_info['tenant_organization'], user['id'], 'owner')
    else:
        keyrock_client.revoke_organization_role(tenant_info['tenant_organization'], user['id'], 'member')

    # Remove user from organization
    tenant_update['users'].remove(user)


@app.route("/tenant/<tenant_id>", methods=['PATCH'])
@authorized
@consumes('application/json')
def update_tenant(user_info, tenant_id):
    try:
        database_controller = DatabaseController(host=MONGO_HOST, port=MONGO_PORT)
        tenant_info = database_controller.get_tenant(tenant_id)

        if tenant_info is None:
            return build_response({
                'error': 'Tenant {} does not exist'.format(tenant_id)
            }, 404)

        if tenant_info['owner_id'] != user_info['id']:
            return build_response({
                'error': 'You are not authorized to delete tenant'
            }, 403)

        # Apply JSON patch
        # Valid operations replace description, add user, remove user
        keyrock_client = KeyrockClient(IDM_URL, IDM_USER, IDM_PASSWD)
        tenant_update = deepcopy(tenant_info)

        for patch in request.json:
            if 'op' not in patch or 'path' not in patch:
                raise ValueError('Invalid JSON PATCH format')

            if patch['op'] == 'replace' and patch['path'] == '/description':
                update_tenant_description(keyrock_client, tenant_info, tenant_update, patch)

            elif patch['op'] == 'add' and patch['path'] == '/users/-':
                add_tenant_user(keyrock_client, tenant_info, tenant_update, patch)

            elif patch['op'] == 'remove' and patch['path'].startswith('/users/'):
                remove_tenant_user(keyrock_client, tenant_info, tenant_update, patch)

            else:
                raise ValueError('Unsupported PATCH operation')

        database_controller.update_tenant(tenant_update)

    except ValueError as e:
        return build_response({
            'error': str(e)
        }, 422)

    return make_response('', 200)


@app.route("/user", methods=['GET'])
@authorized
def get_users(user_info):
    try:
        # This method is just a proxy to the IDM for reading available users
        keyrock_client = KeyrockClient(IDM_URL, IDM_USER, IDM_PASSWD)
        return build_response(keyrock_client.get_users(), 200)
    except KeyrockError as e:
        return build_response({
            'error': str(e)
        }, 503)


@app.before_request
def check_client_accpets_application_json():
    accept_header = request.headers.get('accept', '*/*')
    best_response_mimetype = mimeparse.best_match(('application/json',), accept_header)
    if best_response_mimetype == '':
        msg = "The requested resource is only capable of generating content not acceptable according to the Accept headers sent in the request"
        details = {'supported_mime_types': ['application/json']}
        return build_response({
            'error': msg,
            'details': details
        }, 406)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=(os.environ.get("DEBUG", "false").strip().lower() == "true"))
else:
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
