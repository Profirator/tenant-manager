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

import unittest
from unittest.mock import MagicMock, call

from lib import keyrock_client
from settings import VERIFY_REQUESTS


class KeyrockClientTestCase(unittest.TestCase):

    _x_subject_token = 'token'
    _host = 'http://idm.docker:3000'
    _user = 'user'
    _passwd = 'passwd'

    _headers = {
        'X-Auth-Token': _x_subject_token
    }

    _exp_body = {
        'name': _user,
        'password': _passwd
    }

    def setUp(self):
        keyrock_client.requests = MagicMock()

    def test_authorize_user(self):
        # Mock login
        response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})
        keyrock_client.requests.post.return_value = response

        # Mock authorization request
        user_response = MagicMock(status_code=201)
        expected_info = {
            'id': 'id',
            'username': 'name'
        }
        user_response.json.return_value = expected_info

        keyrock_client.requests.get.return_value = user_response

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)
        token = 'access_token'
        info = client.authorize(token)

        # validate calls
        self.assertEqual(expected_info, info)

        keyrock_client.requests.post.assert_called_once_with('http://idm.docker:3000/v3/auth/tokens', json=self._exp_body, verify=VERIFY_REQUESTS)
        keyrock_client.requests.get.assert_called_once_with('http://idm.docker:3000/user?access_token=access_token')
        user_response.json.assert_called_once_with()

    def test_create_organization(self):
        # Mock HTTP requests
        login_response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})

        create_response = MagicMock(status_code=201)
        organization = {
            'organization': {
                'id': 'org_id'
            }
        }
        create_response.json.return_value = organization

        role_response = MagicMock(status_code=201)

        keyrock_client.requests.post.side_effect = [login_response, create_response, role_response]

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)
        org_id = client.create_organization('organization', 'description', 'owner')

        # Verify calls
        self.assertEqual('org_id', org_id)

        org_body = {
            'organization': {
                'name': 'organization',
                'description': 'description'
            }
        }
        role_body = {
            'user_organization_assignments': {
                'role': 'owner',
                'user_id': 'owner',
                'organization_id': 'org_id'
            }
        }
        post_calls = keyrock_client.requests.post.call_args_list
        self.assertEqual([
            call('http://idm.docker:3000/v3/auth/tokens', json=self._exp_body, verify=VERIFY_REQUESTS),
            call('http://idm.docker:3000/v1/organizations', headers=self._headers, json=org_body, verify=VERIFY_REQUESTS),
            call('http://idm.docker:3000/v1/organizations/org_id/users/owner/organization_roles/owner', headers=self._headers, json=role_body, verify=VERIFY_REQUESTS)
        ], post_calls)

    def test_authorize_organization(self):
        # Mock login
        login_response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})

        # Mock get roles
        roles = {
            'roles': [{
                'name': 'data-provider',
                'id': '1'
            }, {
                'name': 'data-consumer',
                'id': '2'
            }]
        }
        get_roles_response = MagicMock(status_code=200)
        get_roles_response.json.return_value = roles

        # Mock authorize organization
        authorize_response = MagicMock(status_code=201)

        keyrock_client.requests.get.return_value = get_roles_response
        keyrock_client.requests.post.side_effect = [login_response, authorize_response, authorize_response]

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)
        client.authorize_organization('org_id', 'app_id', 'data-provider', 'data-consumer')

        # Validate calls
        get_calls = keyrock_client.requests.get.call_args_list
        self.assertEqual([
            call('http://idm.docker:3000/v1/applications/app_id/roles', headers=self._headers, verify=VERIFY_REQUESTS),
            call('http://idm.docker:3000/v1/applications/app_id/roles', headers=self._headers, verify=VERIFY_REQUESTS)
        ], get_calls)

        owner_body = {
            'role_organization_assignments': {
                'role_id': '1',
                'organization_id': 'org_id',
                'oauth_client_id': 'app_id',
                'role_organization': 'owner'
            }
        }

        member_body = {
            'role_organization_assignments': {
                'role_id': '2',
                'organization_id': 'org_id',
                'oauth_client_id': 'app_id',
                'role_organization': 'member'
            }
        }

        post_calls = keyrock_client.requests.post.call_args_list
        self.assertEqual([
            call('http://idm.docker:3000/v3/auth/tokens', json=self._exp_body, verify=VERIFY_REQUESTS),
            call('http://idm.docker:3000/v1/applications/app_id/organizations/org_id/roles/1/organization_roles/owner', json=owner_body, headers=self._headers, verify=VERIFY_REQUESTS),
            call('http://idm.docker:3000/v1/applications/app_id/organizations/org_id/roles/2/organization_roles/member', json=member_body, headers=self._headers, verify=VERIFY_REQUESTS)
        ], post_calls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
