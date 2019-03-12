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

    def _list_resources(self, url, err):
        response = requests.get(url, headers={
            'X-Auth-Token': self._access_token
        }, verify=VERIFY_REQUESTS)

        if response.status_code != 200:
            raise KeyrockError(err)

        return response.json()

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

    def revoke_organization_role(self, organization_id, owner, role_id):
        """
        Revokes the given organization role from a user
        """
        url = urljoin(self._host, '/v1/organizations/{}/users/{}/organization_roles/{}'.format(organization_id, owner, role_id))

        response = requests.delete(url, headers={
            'X-Auth-Token': self._access_token
        }, verify=VERIFY_REQUESTS)

        if response.status_code != 204:
            raise KeyrockError('Keyrock failed revoking role {} in organization'.format(role_id))

    def grant_application_role(self, app_id, user, role_id):
        """
        """
        url = urljoin(self._host, '/v1/applications/{}/users/{}/roles/{}'.format(app_id, user, role_id))
        response = requests.post(url, headers={
            'X-Auth-Token': self._access_token
        }, verify=VERIFY_REQUESTS)

        if response.status_code != 201:
            raise KeyrockError('Keyrock failed assigning role')

    def create_role(self, app_id, name):
        """
        """
        url = urljoin(url, '/v1/applications/{}/roles'.format(app_id))
        body = {
            'role': {
                'name': name
            }
        }

        response = requests.post(url, headers={
            'X-Auth-Token': self._access_token
        }, json=body, verify=VERIFY_REQUESTS)

        if response.status_code != 201:
            raise KeyrockError('Keyrock failed creating role')

        return response.json()['role']['id']

    def get_application_roles(self, app_id):
        """
        """
        url = urljoin(url, '/v1/applications/{}/roles'.format(app_id))
        return self._list_resources(url, 'Keyrock failed retrieving application roles')

    def get_application(self, app_id):
        """
        """
        url = urljoin(self._host, '/v1/applications/{}'.format(app_id))
        return self._list_resources(url, 'Application cannot be found')

    def create_application(self, name, description, app_url, app_redirect):
        """
        """
        url = urljoin(self._host, '/v1/applications')
        body = {
            "application": {
                "name": name,
                "description": description,
                "redirect_uri": app_redirect,
                "url": app_url,
                "grant_type": [
                    "authorization_code",
                    "implicit",
                    "password"
                ]
            }
        }

        response = requests.post(url, headers={
            'X-Auth-Token': self._access_token
        }, json=body, verify=VERIFY_REQUESTS)

        if response.status_code != 201:
            raise KeyrockError('Keyrock failed creating application')

        return response.json()['application']['id']

    def create_organization(self, name, description, owner):
        """
        Creates a new organization and asigns the given user as owner
        """
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

    def delete_organization(self, org_id):
        url = urljoin(self._host, '/v1/organizations/{}'.format(org_id))
        response = requests.delete(url, headers={
            'X-Auth-Token': self._access_token
        }, verify=VERIFY_REQUESTS)

        if response.status_code != 204:
            raise KeyrockError('Keyrock failed deleting organization')

    def update_organization(self, org_id, update):
        url = urljoin(self._host, '/v1/organizations/{}'.format(org_id))
        body = {
            'organization': update
        }

        response = requests.patch(url, headers={
            'X-Auth-Token': self._access_token
        }, json=body, verify=VERIFY_REQUESTS)

        if response.status_code != 200:
            raise KeyrockError('Keyrock failed updating organization')

    def _search_id(self, url, name, search_elem, key):
        response = requests.get(url, headers={
            'X-Auth-Token': self._access_token
        }, verify=VERIFY_REQUESTS)

        if response.status_code != 200:
            raise KeyrockError('{} {} cannot be found'.format(search_elem, name))

        id_ = None
        for elem in response.json()[search_elem.lower() + 's']:
            if elem[key] == name:
                id_ = elem['id']
                break
        else:
            raise KeyrockError('{} {} cannot be found'.format(search_elem, name))

        return id_

    def get_user_id(self, user_name):
        url = urljoin(self._host, '/v1/users')
        return self._search_id(url, user_name, 'User', 'username')

    def get_role_id(self, app_id, role):
        """
        Returns the ID of a role given its name and the application it belongs
        """
        url = urljoin(self._host, '/v1/applications/{}/roles'.format(app_id))
        return self._search_id(url, role, 'Role', 'name')

    def authorize_organization_role(self, organization_id, app_id, app_role, org_role):
        role_id = self.get_role_id(app_id, app_role)
        url = urljoin(self._host,
            '/v1/applications/{}/organizations/{}/roles/{}/organization_roles/{}'.format(app_id, organization_id, role_id, org_role))

        body = {
            'role_organization_assignments': {
                'role_id': role_id,
                'organization_id': organization_id,
                'oauth_client_id': app_id,
                'role_organization': org_role
            }
        }

        response = requests.post(url, headers={
            'X-Auth-Token': self._access_token
        }, json=body, verify=VERIFY_REQUESTS)

        if response.status_code != 201:
            raise KeyrockError('Role {} cannot be asigned to organization'.format(app_role))

    def authorize_organization(self, organization_id, app_id, admin_role, member_role):
        """
        Authorizes a given organization in a particular application by
        granting it a set of roles
        """

        self.authorize_organization_role(organization_id, app_id, admin_role, 'owner')
        self.authorize_organization_role(organization_id, app_id, member_role, 'owner')
        self.authorize_organization_role(organization_id, app_id, member_role, 'member')

    def get_user(self, user_id):
        """
        Returns detailed info of a given user
        """
        url = urljoin(self._host, '/v1/users/{}'.format(user_id))

        response = requests.get(url, headers={
            'X-Auth-Token': self._access_token
        }, verify=VERIFY_REQUESTS)

        if response.status_code != 200:
            raise KeyrockError('It could not be possible to retrieve user info')

        return response.json()['user']

    def get_users(self):
        """
        Returns the list of available users
        """
        url = urljoin(self._host, '/v1/users')
        response = requests.get(url, headers={
            'X-Auth-Token': self._access_token
        }, verify=VERIFY_REQUESTS)

        if response.status_code != 200:
            raise KeyrockError('It could not be possible to retrieve user info')

        return response.json()

    def get_organization_members(self, organization_id):
        """
        Returns the list of users that are members of a given organization
        """
        url = urljoin(self._host, '/v1/organizations/{}/users'.format(organization_id))

        response = requests.get(url, headers={
            'X-Auth-Token': self._access_token
        }, verify=VERIFY_REQUESTS)

        if response.status_code != 200:
            raise KeyrockError('It could not be possible to retrieve organization members')

        members = response.json()['organization_users']
        for member in members:
            member['name'] = self.get_user(member['user_id'])['username']

        return members
