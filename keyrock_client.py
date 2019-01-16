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

import requests

from urllib.parse import urljoin
from settings import VERIFY_REQUESTS

class KeyrockError(Exception):
    pass


class KeyrockClient():

    _access_token = None
    _host = None

    def __init__(self, host, user, passwd):
        self._host = host
        self.login(user, passwd)

    def login(self, user, passwd):
        body = {
            'name': user,
            'password': passwd
        }

        url = urljoin(self._host, '/v3/auth/tokens')
        response = requests.post(url, json=body, verify=VERIFY_REQUESTS)

        response.raise_for_status()
        self._access_token = response.headers['x-subject-token']

    def authorize(self, token):
        """
        Validates the given access token and returns user info if valid
        """
        url = urljoin(self._host, '/user?access_token=' + token)
        response = requests.get(url)

        if response.status_code != 201:
            raise KeyrockError('Invalid access token')

        return response.json()

    def grant_organization_role(self, organization_id, owner, role_id):
        """
        Grants the given organization role to a user
        """
        url = urljoin(self._host, '/v1/organizations/{}/users/{}/organization_roles/{}'.format(organization_id, owner, role_id))
        body = {
            'user_organization_assignments': {
                'role': role_id,
                'user_id': owner,
                'organization_id': organization_id
            }
        }

        response = requests.post(url, headers={
            'X-Auth-Token': self._access_token
        }, json=body, verify=VERIFY_REQUESTS)

        if response.status_code != 201:
            raise KeyrockError('Keyrock failed assigning role {} in organization'.format(role_id))

    def create_organization(self, name, description, owner):
        """
        Creates a new organization and asigns the given user as owner
        """
        # TODO: Validate organzation name as it is not an ID

        # Create organization using provided info
        url = urljoin(self._host, '/v1/organizations')
        response = requests.post(url, headers={
            'X-Auth-Token': self._access_token
        }, json={
            'organization': {
                'name': name,
                'description': description
            }
        }, verify=VERIFY_REQUESTS)

        if response.status_code != 201:
            raise KeyrockError('Keyrock failed creating the organization')

        # Make the provided user owner of the organization
        organization_id = response.json()['organization']['id']
        self.grant_organization_role(organization_id, owner, 'owner')

        return organization_id

    def get_role_id(self, app_id, role):
        """
        Returns the ID of a role given its name and the application it belongs
        """
        url = urljoin(self._host, '/v1/applications/{}/roles'.format(app_id))

        response = requests.get(url, headers={
            'X-Auth-Token': self._access_token
        }, verify=VERIFY_REQUESTS)

        if response.status_code != 200:
            raise KeyrockError('Role {} cannot be found'.format(role))

        role_id = None
        for role_info in response.json()['roles']:
            if role_info['name'].lower() == role.lower():
                role_id = role_info['id']
                break
        else:
            raise KeyrockError('Role {} cannot be found'.format(role))

        return role_id

    def authorize_organization(self, organization_id, app_id, roles):
        """
        Authorizes a given organization in a particular application by
        granting it a set of roles
        """

        for role in roles:
            role_id = self.get_role_id(app_id, role)
            url = urljoin(self._host,
                '/v1/applications/{}/organizations/{}/roles/{}/organization_roles/member'.format(app_id, organization_id, role_id))

            body = {
                'role_organization_assignments': {
                    'role_id': role_id,
                    'organization_id': organization_id,
                    'oauth_client_id': app_id,
                    'role_organization': 'member'
                }
            }

            response = requests.post(url, {
                'X-Auth-Token': self._access_token
            }, json=body, verify=VERIFY_REQUESTS)

            if response.status_code != 201:
                raise KeyrockError('Role {} cannot be asigned to organization'.format(role))
