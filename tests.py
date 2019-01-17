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

import keyrock_client
from settings import VERIFY_REQUESTS


class KeyrockClientTestCase(unittest.TestCase):

    _x_subject_token = 'token'
    _host = 'http://idm.docker:3000'
    _user = 'user'
    _passwd = 'passwd'

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

        exp_body = {
            'name': self._user,
            'password': self._passwd
        }
        keyrock_client.requests.post.assert_called_once_with('http://idm.docker:3000/v3/auth/tokens', json=exp_body, verify=VERIFY_REQUESTS)
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

        headers = {
            'X-Auth-Token': self._x_subject_token
        }
        exp_body = {
            'name': self._user,
            'password': self._passwd
        }
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
            call('http://idm.docker:3000/v3/auth/tokens', json=exp_body, verify=VERIFY_REQUESTS),
            call('http://idm.docker:3000/v1/organizations', headers=headers, json=org_body, verify=VERIFY_REQUESTS),
            call('http://idm.docker:3000/v1/organizations/org_id/users/owner/organization_roles/owner', headers=headers, json=role_body, verify=VERIFY_REQUESTS)
        ], post_calls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
