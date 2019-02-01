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
from importlib import reload

import controller
from lib import keyrock_client, umbrella_client, utils
from settings import VERIFY_REQUESTS


class UtilsTestCase(unittest.TestCase):

    _user_info = {
        'id': 'user-id'
    }
    _token = 'access-token'

    def setUp(self):
        self._keyrock_client = MagicMock()
        self._keyrock_client.authorize.return_value = self._user_info

        utils.KeyrockClient = MagicMock(return_value=self._keyrock_client)
        self._response = MagicMock()

        utils.make_response = MagicMock(return_value=self._response)
        utils.request = MagicMock()

    def test_authorization_decorator(self):
        expected_response = {}
        exp_id = '1'

        def wrapped(user_info, id_param):
            self.assertEqual(self._user_info, user_info)
            self.assertEqual(exp_id, id_param)
            return expected_response

        utils.request.headers = {
            'authorization': 'Bearer {}'.format(self._token)
        }

        # Validate decorator
        wrapper = utils.authorized(wrapped)
        resp = wrapper(exp_id)

        self.assertEqual(expected_response, resp)
        self._keyrock_client.authorize.assert_called_once_with(self._token)

    def test_authorization_decorator_missing_token(self):
        def wrapped(user_info):
            pass

        utils.request.headers = {}

        # Validate decorator
        wrapper = utils.authorized(wrapped)
        resp = wrapper()

        self.assertEqual(self._response, resp)
        utils.make_response.assert_called_once_with('{"error": "This request requires authentication"}', 401)

        self.assertEqual(0, self._keyrock_client.authorize.call_count)

    def test_authorization_decorator_invalid_token(self):
        def wrapped(user_info):
            pass

        self._keyrock_client.authorize.side_effect = Exception('Error')

        utils.request.headers = {
            'authorization': 'Bearer {}'.format(self._token)
        }

        # Validate decorator
        wrapper = utils.authorized(wrapped)
        resp = wrapper()

        self.assertEqual(self._response, resp)
        utils.make_response.assert_called_once_with('{"error": "This request requires authentication"}', 401)

        self._keyrock_client.authorize.assert_called_once_with(self._token)


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


class UmbrellaClientTestCase(unittest.TestCase):

    _host = 'http://umbrella.docker/'
    _admin_token = 'token'
    _api_key = 'api_key'

    def test_add_sub_setting(self):
        # Mock get request
        apis = {
            'data': [{
                'settings': {
                    'idp_app_id': '1'
                }
            }, {
                'id': 'id',
                'settings': {
                    'idp_app_id': '2'
                }
            }]
        }
        get_response = MagicMock(status_code=200)
        get_response.json.return_value = apis

        umbrella_client.requests = MagicMock()
        umbrella_client.requests.get.return_value = get_response

        # Mock put request
        umbrella_client.requests.put.return_value = MagicMock(status_code=204)

        client = umbrella_client.UmbrellaClient(self._host, self._admin_token, self._api_key)
        client.add_sub_url_setting_app_id('2', [{
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
            'id': 'id',
            'settings': {
                'idp_app_id': '2'
            },
            'sub_settings': [{
                'regex': '/',
                'http_method': 'any'
            }, {
                'regex': '/',
                'http_method': 'get'
            }]
        }

        # Verify calls
        umbrella_client.requests.get.assert_called_once_with(
            'http://umbrella.docker/api-umbrella/v1/apis.json?search[value]=2&search[regex]=false&start=0&length=100',
            headers=headers, verify=VERIFY_REQUESTS)

        umbrella_client.requests.put.assert_called_once_with(
            'http://umbrella.docker/api-umbrella/v1/apis/id',
            headers=headers, json=exp_body, verify=VERIFY_REQUESTS
        )


class ControllerTestCase(unittest.TestCase):

    _broker_app = 'broker_app'
    _admin_role = 'broker_admin'
    _consumer_role = 'broker_consumer'
    _bae_app = 'bae_app'
    _bae_seller = 'seller'
    _bae_customer = 'customer'
    _bae_admin = 'admin'
    _user_info = {
        'id': 'user-id'
    }

    def setUp(self):
        def mock_decorator(func):
            def  wrapper(*args, **kwargs):
                return func(*args, **kwargs)

            wrapper.__name__ = func.__name__
            return wrapper

        utils.authorized = mock_decorator
        reload(controller)

        # Mock controller dependencies
        controller.request = MagicMock()

        self._response = MagicMock()
        controller.make_response = MagicMock(return_value=self._response)

        self._keyrock_client = MagicMock()

        controller.KeyrockClient = MagicMock(return_value=self._keyrock_client)

        self._umbrella_client = MagicMock()
        controller.UmbrellaClient = MagicMock(return_value=self._umbrella_client)

        self._database_controller = MagicMock()
        controller.DatabaseController = MagicMock(return_value=self._database_controller)

        controller.build_response = MagicMock(return_value=self._response)

        controller.BROKER_APP_ID = self._broker_app
        controller.BROKER_ADMIN_ROLE = self._admin_role
        controller.BROKER_CONSUMER_ROLE = self._consumer_role
        controller.BAE_APP_ID = self._bae_app
        controller.BAE_SELLER_ROLE = self._bae_seller
        controller.BAE_CUSTOMER_ROLE = self._bae_customer
        controller.BAE_ADMIN_ROLE = self._bae_admin

    def tearDown(self):
        reload(utils)

    def test_create_tenant(self):
        # Mock request contents
        controller.request.json = {
            'name': 'tenant',
            'description': 'tenant description'
        }

        self._keyrock_client.create_organization.return_value = 'org_id'

        response = controller.create(self._user_info)

        # Validate calls
        self.assertEqual(self._response, response)
        controller.make_response.assert_called_once_with('', 201)

        self._keyrock_client.create_organization.assert_called_once_with('tenant', 'tenant description', 'user-id')

        self._keyrock_client.authorize_organization.assert_called_once_with(
            'org_id', self._broker_app, self._admin_role, self._consumer_role
        )

        authorize_calls = self._keyrock_client.authorize_organization_role.call_args_list
        self.assertEqual([
            call('org_id', self._bae_app, self._bae_seller, 'owner'),
            call('org_id', self._bae_app, self._bae_customer, 'owner'),
            call('org_id', self._bae_app, self._bae_admin, 'owner')
        ], authorize_calls)

        policy = [{
            "http_method": 'get',
            "regex": "^/",
            "settings": {
                "required_headers": [{
                    "key": "Fiware-Service",
                    "value": 'tenant'
                }],
                "required_roles": [
                    'tenant.' + self._consumer_role
                ],
                "required_roles_override": True
            }
        }, {
            "http_method": 'any',
            "regex": "^/",
            "settings": {
                "required_headers": [{
                    "key": "Fiware-Service",
                    "value": 'tenant'
                }],
                "required_roles": [
                    'tenant.' + self._admin_role
                ],
                "required_roles_override": True
            }
        }]

        self._umbrella_client.add_sub_url_setting_app_id.assert_called_once_with(
            self._broker_app, policy
        )

        self._database_controller.save_tenant.assert_called_once_with(
            'tenant', 'tenant description', 'user-id', 'org_id')

    def test_get_tenants(self):
        org_id = 'org_id'

        exp_tenants = [{
            'tenant_organization': org_id,
            'users': [{
                'id': 'user-id',
                'name': 'username',
                'roles': [self._consumer_role, self._admin_role]
            }]
        }]

        tenants = [{
            'tenant_organization': org_id
        }]

        members = [{
            'user_id': 'user-id',
            'name': 'username',
            'role': 'owner'
        }]

        self._database_controller.read_tenants.return_value = tenants
        self._keyrock_client.get_organization_members.return_value = members

        tenants_response = controller.get(self._user_info)

        self.assertEqual(tenants_response, self._response)
        controller.build_response.assert_called_once_with(exp_tenants, 200)
        self._database_controller.read_tenants.assert_called_once_with('user-id')

    def test_get_tenant(self):
        org_id = 'org_id'
        tenant_id = 'tenant_id'

        exp_tenant = {
            'tenant_organization': org_id,
            'user_id': 'user-id',
            'users': [{
                'id': 'user-id',
                'name': 'username',
                'roles': [self._consumer_role, self._admin_role]
            }]
        }

        tenant = {
            'tenant_organization': org_id,
            'user_id': 'user-id'
        }

        members = [{
            'user_id': 'user-id',
            'name': 'username',
            'role': 'owner'
        }]

        self._database_controller.get_tenant.return_value = tenant
        self._keyrock_client.get_organization_members.return_value = members

        #import ipdb; ipdb.set_trace()
        tenant_response = controller.get_tenant(self._user_info, tenant_id)

        self.assertEqual(tenant_response, self._response)
        controller.build_response.assert_called_once_with(exp_tenant, 200)
        self._database_controller.get_tenant.assert_called_once_with(tenant_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
