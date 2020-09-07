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
from unittest.mock import ANY, call, MagicMock, patch
from importlib import reload

import controller
from lib import keyrock_client, umbrella_client, utils
from settings import VERIFY_REQUESTS


class UmbrellaClientTestCase(unittest.TestCase):

    _host = 'https://umbrella.docker'
    _admin_token = ''
    _api_key = ''

    def test_add_sub_setting(self):
        # Mock get request
        apis = {
            'data': [{
                'id': '1',
                'name': 'Orion Context Broker',
                'settings': {
                    'idp_app_id': '1111'
                },
                'sub_settings': []
            },
            {
                'id': '2',
                'name': 'Orion-LD Context Broker',
                'settings': {
                    'idp_app_id': '1111'
                },
                'sub_settings': []
            }
            ]
        }

        changes = {
            'config': {
                'apis': {
                    'modified': [{
                        'id': '1111'
                    }]
                }
            }
        }

        get_response = MagicMock(status_code=200)
        get_response.json.side_effect = [apis, changes]

        umbrella_client.requests = MagicMock()
        umbrella_client.requests.get.return_value = get_response

        # Mock put request
        umbrella_client.requests.put.return_value = MagicMock(status_code=204)

        # Mock post request
        umbrella_client.requests.post.return_value = MagicMock(status_code=201)

        client = umbrella_client.UmbrellaClient(self._host, self._admin_token, self._api_key)
        client.add_sub_url_setting_app_id('1111', [{
            'regex': '/',
            'http_method': 'any'
        }, {
            'regex': '/',
            'http_method': 'get'
        }])

        headers = {
            'X-Api-Key': self._api_key,
            'X-Admin-Auth-Token': self._admin_token
        }

        exp_body = {
            'api': {
                'id': 'id',
                'settings': {
                    'idp_app_id': '1111'
                },
                'sub_settings': [{
                    'regex': '/',
                    'http_method': 'any'
                }, {
                    'regex': '/',
                    'http_method': 'get'
                }]
            }
        }

        exp_changes = {
            'config': {
                'apis': {
                    '1': {
                        'publish': 1
                    }
                },
                'website_backends': {}
            }
        }

        # Verify calls
        get_calls = umbrella_client.requests.get.call_args_list
        self.assertEqual([
            call('https://umbrella.docker/api-umbrella/v1/apis.json?start=0&length=100',headers=headers, verify=VERIFY_REQUESTS),
            call('https://umbrella.docker/api-umbrella/v1/config/pending_changes',headers=headers, verify=VERIFY_REQUESTS)
        ], get_calls)

        umbrella_client.requests.put.assert_called_once_with(
            'https://umbrella.docker/api-umbrella/v1/apis/id',
            headers=headers, json=exp_body, verify=VERIFY_REQUESTS
        )

        umbrella_client.requests.post.assert_called_once_with(
            'https://umbrella.docker/api-umbrella/v1/config/publish',
            headers=headers, json=exp_changes, verify=VERIFY_REQUESTS
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
