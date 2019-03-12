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

        self._keyrock_client.authorize.side_effect = keyrock_client.KeyrockError('Error')

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

    def test_authorize_user_invalid_token(self):
        response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})
        keyrock_client.requests.post.return_value = response

        keyrock_client.requests.get.return_value = MagicMock(status_code=403)

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)
        error = False
        try:
            client.authorize('token')
        except keyrock_client.KeyrockError as e:
            self.assertEqual('Invalid access token', str(e))
            error = True

        self.assertTrue(error)

    def test_get_user_id_request_error(self):
        response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})

        keyrock_client.requests.post.return_value = response

        keyrock_client.requests.get.return_value = MagicMock(status_code=400)

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)
        error = False
        try:
            client.get_user_id('user_name')
        except keyrock_client.KeyrockError as e:
            self.assertEqual('User user_name cannot be found', str(e))
            error = True

        self.assertTrue(error)

    def test_get_user_id_not_found(self):
        response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})

        keyrock_client.requests.post.return_value = response

        get_response = MagicMock(status_code=200)
        get_response.json.return_value = {
            'users': []
        }

        keyrock_client.requests.get.return_value = get_response

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)
        error = False
        try:
            client.get_user_id('user_name')
        except keyrock_client.KeyrockError as e:
            self.assertEqual('User user_name cannot be found', str(e))
            error = True

        self.assertTrue(error)

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

    def test_create_organization_error(self):
        login_response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})

        keyrock_client.requests.post.side_effect = [login_response, MagicMock(status_code=400)]

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)

        error = False
        try:
            client.create_organization('organization', 'description', 'owner')
        except keyrock_client.KeyrockError as e:
            self.assertEqual('Keyrock failed creating the organization', str(e))
            error = True

        self.assertTrue(error)

    def test_grant_organization_role_error(self):
        login_response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})

        keyrock_client.requests.post.side_effect = [login_response, MagicMock(status_code=400)]

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)

        error = False
        try:
            client.grant_organization_role('org_id', 'user_id', 'owner')
        except keyrock_client.KeyrockError as e:
            self.assertEqual('Keyrock failed assigning role owner in organization', str(e))
            error = True

        self.assertTrue(error)

    def test_delete_organization(self):
        login_response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})
        keyrock_client.requests.post.side_effect = [login_response]

        keyrock_client.requests.delete.return_value = MagicMock(status_code=204)

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)
        client.delete_organization('org_id')

        keyrock_client.requests.post.assert_called_once_with('http://idm.docker:3000/v3/auth/tokens', json=self._exp_body, verify=VERIFY_REQUESTS)
        keyrock_client.requests.delete.assert_called_once_with('http://idm.docker:3000/v1/organizations/org_id', headers=self._headers, verify=VERIFY_REQUESTS)

    def test_delete_organization_error(self):
        login_response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})

        keyrock_client.requests.post.return_value = login_response
        keyrock_client.requests.delete.return_value = MagicMock(status_code=403)

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)

        error = False
        try:
            client.delete_organization('org_id')
        except keyrock_client.KeyrockError as e:
            self.assertEqual('Keyrock failed deleting organization', str(e))
            error = True

        self.assertTrue(error)

    def test_revoke_organization_roles(self):
        login_response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})
        keyrock_client.requests.post.side_effect = [login_response]

        keyrock_client.requests.delete.return_value = MagicMock(status_code=204)

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)
        client.revoke_organization_role('org_id', 'user', 'owner')

        keyrock_client.requests.post.assert_called_once_with('http://idm.docker:3000/v3/auth/tokens', json=self._exp_body, verify=VERIFY_REQUESTS)
        keyrock_client.requests.delete.assert_called_once_with('http://idm.docker:3000/v1/organizations/org_id/users/user/organization_roles/owner', headers=self._headers, verify=VERIFY_REQUESTS)

    def test_revoke_organization_role_error(self):
        login_response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})

        keyrock_client.requests.post.side_effect = [login_response, MagicMock(status_code=400)]

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)

        error = False
        try:
            client.revoke_organization_role('org_id', 'user_id', 'owner')
        except keyrock_client.KeyrockError as e:
            self.assertEqual('Keyrock failed revoking role owner in organization', str(e))
            error = True

        self.assertTrue(error)

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
        keyrock_client.requests.post.side_effect = [login_response, authorize_response, authorize_response, authorize_response]

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)
        client.authorize_organization('org_id', 'app_id', 'data-provider', 'data-consumer')

        # Validate calls
        get_calls = keyrock_client.requests.get.call_args_list
        self.assertEqual([
            call('http://idm.docker:3000/v1/applications/app_id/roles', headers=self._headers, verify=VERIFY_REQUESTS),
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

        owner_member_body = {
            'role_organization_assignments': {
                'role_id': '2',
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
            call('http://idm.docker:3000/v1/applications/app_id/organizations/org_id/roles/2/organization_roles/owner', json=owner_member_body, headers=self._headers, verify=VERIFY_REQUESTS),
            call('http://idm.docker:3000/v1/applications/app_id/organizations/org_id/roles/2/organization_roles/member', json=member_body, headers=self._headers, verify=VERIFY_REQUESTS)
        ], post_calls)

    def test_get_organization_members(self):
        org_id = 'org_id'
        login_response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})

        members = {
            'organization_users': [{
                'user_id': 'user_id'
            }]
        }
        get_members_response = MagicMock(status_code=200)
        get_members_response.json.return_value = members

        user = {
            'user': {
                'username': 'username'
            }
        }
        get_user_response = MagicMock(status_code=200)
        get_user_response.json.return_value = user

        keyrock_client.requests.post.return_value = login_response
        keyrock_client.requests.get.side_effect = [get_members_response, get_user_response]

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)
        members_response = client.get_organization_members(org_id)

        exp_response = [{
            'user_id': 'user_id',
            'name': 'username'
        }]
        self.assertEqual(exp_response, members_response)

        get_calls = keyrock_client.requests.get.call_args_list
        self.assertEqual([
            call('http://idm.docker:3000/v1/organizations/org_id/users', headers=self._headers, verify=VERIFY_REQUESTS),
            call('http://idm.docker:3000/v1/users/user_id', headers=self._headers, verify=VERIFY_REQUESTS)
        ], get_calls)

    def test_get_users(self):
        login_response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})

        users = {
            'users': [{
                'username': 'username'
            }]
        }
        get_users_response = MagicMock(status_code=200)
        get_users_response.json.return_value = users

        keyrock_client.requests.post.return_value = login_response
        keyrock_client.requests.get.return_value = get_users_response

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)
        resp_users = client.get_users()

        self.assertEqual(users, resp_users)

    def test_update_organization(self):
        login_response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})
        keyrock_client.requests.post.return_value = login_response

        keyrock_client.requests.patch.return_value = MagicMock(status_code=200)

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)
        client.update_organization('org_id', {'description': 'New description'})

        exp_body = {
            'organization': {
                'description': 'New description'
            }
        }
        keyrock_client.requests.patch.assert_called_once_with(
            'http://idm.docker:3000/v1/organizations/org_id', headers=self._headers, json=exp_body, verify=VERIFY_REQUESTS)

    def test_update_organization_error(self):
        login_response = MagicMock(status_code=201, headers={'x-subject-token': self._x_subject_token})
        keyrock_client.requests.post.return_value = login_response

        keyrock_client.requests.patch.return_value = MagicMock(status_code=400)

        client = keyrock_client.KeyrockClient(self._host, self._user, self._passwd)

        error = False
        try:
            client.update_organization('org_id', 'New description')
        except keyrock_client.KeyrockError as e:
            self.assertEqual('Keyrock failed updating organization', str(e))
            error = True

        self.assertTrue(error)


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
            'api': {
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
        }

        # Verify calls
        umbrella_client.requests.get.assert_called_once_with(
            'http://umbrella.docker/api-umbrella/v1/apis.json?start=0&length=100',
            headers=headers, verify=VERIFY_REQUESTS)

        umbrella_client.requests.put.assert_called_once_with(
            'http://umbrella.docker/api-umbrella/v1/apis/id',
            headers=headers, json=exp_body, verify=VERIFY_REQUESTS
        )


@patch("lib.utils.get_content_type", new=MagicMock(return_value="application/json"))
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
            def wrapper(*args, **kwargs):
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
            'name': 'New Tenant',
            'description': 'tenant description'
        }

        self._keyrock_client.create_organization.return_value = 'org_id'
        self._database_controller.get_tenant.return_value = None

        response = controller.create(self._user_info)

        # Validate calls
        self.assertEqual(self._response, response)
        controller.make_response.assert_called_once_with('', 201)

        self._keyrock_client.create_organization.assert_called_once_with('New Tenant', 'tenant description', 'user-id')

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
            "http_method": 'GET',
            "regex": "^/",
            "settings": {
                "required_headers": [{
                    "key": "Fiware-Service",
                    "value": 'new_tenant'
                }],
                "required_roles": [
                    'org_id.' + self._consumer_role
                ],
                "required_roles_override": True
            }
        }, {
            "http_method": 'any',
            "regex": "^/",
            "settings": {
                "required_headers": [{
                    "key": "Fiware-Service",
                    "value": 'new_tenant'
                }],
                "required_roles": [
                    'org_id.' + self._admin_role
                ],
                "required_roles_override": True
            }
        }]

        self._umbrella_client.add_sub_url_setting_app_id.assert_called_once_with(
            self._broker_app, policy
        )

        self._database_controller.save_tenant.assert_called_once_with(
            'new_tenant', 'New Tenant', 'tenant description', 'user-id', [], 'org_id')

    def test_create_tenant_with_users(self):
        # Mock request contents
        controller.request.json = {
            "name": "New Tenant",
            "description": "tenant description",
            "users": [
                {
                    "name": "username",
                    "roles": [self._admin_role],
                },
                {
                    "name": "user2",
                    "roles": [self._consumer_role],
                },
            ],
        }

        self._keyrock_client.create_organization.return_value = 'org_id'
        self._database_controller.get_tenant.return_value = None
        self._keyrock_client.get_user_id.side_effect = ["username_id", "user2_id"]

        response = controller.create(self._user_info)

        # Validate calls
        self.assertEqual(self._response, response)
        controller.make_response.assert_called_once_with('', 201)

        self._keyrock_client.create_organization.assert_called_once_with('New Tenant', 'tenant description', 'user-id')

        self._keyrock_client.authorize_organization.assert_called_once_with(
            'org_id', self._broker_app, self._admin_role, self._consumer_role
        )

        authorize_calls = self._keyrock_client.authorize_organization_role.call_args_list
        self.assertEqual(
            authorize_calls,
            [
                call('org_id', self._bae_app, self._bae_seller, 'owner'),
                call('org_id', self._bae_app, self._bae_customer, 'owner'),
                call('org_id', self._bae_app, self._bae_admin, 'owner')
            ]
        )

        grant_organization_role_calls = self._keyrock_client.grant_organization_role.call_args_list
        self.assertEqual(
            [
                call('org_id', 'username_id', 'owner'),
                call('org_id', 'user2_id', 'member')
            ],
            grant_organization_role_calls
        )
        policy = [{
            "http_method": 'GET',
            "regex": "^/",
            "settings": {
                "required_headers": [{
                    "key": "Fiware-Service",
                    "value": 'new_tenant'
                }],
                "required_roles": [
                    'org_id.' + self._consumer_role
                ],
                "required_roles_override": True
            }
        }, {
            "http_method": 'any',
            "regex": "^/",
            "settings": {
                "required_headers": [{
                    "key": "Fiware-Service",
                    "value": 'new_tenant'
                }],
                "required_roles": [
                    'org_id.' + self._admin_role
                ],
                "required_roles_override": True
            }
        }]

        self._umbrella_client.add_sub_url_setting_app_id.assert_called_once_with(
            self._broker_app, policy
        )

        exp_users = [{
            'id': 'username_id',
            'name': 'username',
            'roles': [self._admin_role]
        }, {
            'id': 'user2_id',
            'name': 'user2',
            'roles': [self._consumer_role]
        }]

        self._database_controller.save_tenant.assert_called_once_with(
            'new_tenant', 'New Tenant', 'tenant description', 'user-id', exp_users, 'org_id')

    def test_create_tenant_missing_name(self):
        # Mock request contents
        controller.request.json = {
            'description': 'tenant description'
        }

        response = controller.create(self._user_info)

        self.assertEqual(response, self._response)
        controller.build_response.assert_called_once_with({'error': ANY}, 422)
        controller.DatabaseController.assert_not_called()

    def test_create_tenant_missing_description(self):
        # Mock request contents
        controller.request.json = {
            'name': 'New Tenant'
        }

        response = controller.create(self._user_info)

        self.assertEqual(response, self._response)
        controller.build_response.assert_called_once_with({'error': ANY}, 422)
        controller.DatabaseController.assert_not_called()

    def test_create_tenant_missing_user_name(self):
        # Mock request contents
        controller.request.json = {
            'name': 'New Tenant',
            'description': 'tenant description',
            'users': [{
                'roles': [self._consumer_role, self._admin_role]
            }]
        }

        response = controller.create(self._user_info)

        self.assertEqual(response, self._response)
        controller.build_response.assert_called_once_with({'error': ANY}, 422)
        controller.DatabaseController.assert_not_called()

    def test_create_tenant_missing_user_roles(self):
        # Mock request contents
        controller.request.json = {
            'name': 'New Tenant',
            'description': 'tenant description',
            'users': [{
                'name': 'username'
            }]
        }

        response = controller.create(self._user_info)

        self.assertEqual(response, self._response)
        controller.build_response.assert_called_once_with({'error': ANY}, 422)
        controller.DatabaseController.assert_not_called()

    def test_create_tenant_duplicated_tenant(self):
        # Mock request contents
        controller.request.json = {
            'name': 'New Tenant',
            'description': 'tenant description'
        }
        self._database_controller.get_tenant.return_value = {}

        response = controller.create(self._user_info)

        self.assertEqual(response, self._response)
        controller.build_response.assert_called_once_with({'error': ANY}, 409)
        controller.KeyrockClient.assert_not_called()

    def test_create_tenant_unexpected_error(self):
        # Mock request contents
        controller.request.json = {
            'name': 'New Tenant',
            'description': 'tenant description'
        }
        self._database_controller.get_tenant.return_value = None
        self._database_controller.save_tenant.side_effect = ValueError

        self.assertRaises(ValueError, controller.create, self._user_info)

    def test_create_tenant_error_connecting_keyrock(self):
        # Mock request contents
        controller.request.json = {
            'name': 'New Tenant',
            'description': 'tenant description'
        }
        self._database_controller.get_tenant.return_value = None
        self._keyrock_client.create_organization.side_effect = keyrock_client.KeyrockError("Error")

        response = controller.create(self._user_info)

        self.assertEqual(response, self._response)
        controller.build_response.assert_called_once_with({'error': 'Error'}, 503)

    def test_get_tenants(self):
        org_id = 'org_id'

        tenants = [{
            'tenant_organization': org_id,
            'users': [{
                'id': 'user-id',
                'name': 'username',
                'roles': [self._consumer_role, self._admin_role]
            }]
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
        controller.build_response.assert_called_once_with(tenants, 200)
        self._database_controller.read_tenants.assert_called_once_with('user-id')

    def test_get_tenant(self):
        org_id = 'org_id'
        tenant_id = 'tenant_id'

        exp_tenant = {
            'tenant_organization': org_id,
            'owner_id': 'user-id',
            'users': [{
                'id': 'user-id',
                'name': 'username',
                'roles': [self._consumer_role, self._admin_role]
            }]
        }

        tenant = {
            'tenant_organization': org_id,
            'owner_id': 'user-id'
        }

        members = [{
            'user_id': 'user-id',
            'name': 'username',
            'role': 'owner'
        }]

        self._database_controller.get_tenant.return_value = tenant
        self._keyrock_client.get_organization_members.return_value = members

        tenant_response = controller.get_tenant(self._user_info, tenant_id)

        self.assertEqual(tenant_response, self._response)
        controller.build_response.assert_called_once_with(exp_tenant, 200)
        self._database_controller.get_tenant.assert_called_once_with(tenant_id)

    def test_delete_tenant(self):
        tenant_id = 'tenant_id'
        org_id = 'org_id'

        tenant = {
            'tenant_organization': org_id,
            'owner_id': 'user-id'
        }

        self._database_controller.get_tenant.return_value = tenant

        broker_api = {
            'sub_settings': [{
                'settings': {
                    'required_headers': [{
                        'key': 'Fiware-Service',
                        'value': 'new_tenant'
                    }]
                }
            }, {
                'settings': {
                    'required_headers': [{
                        'key': 'Fiware-Service',
                        'value': tenant_id
                    }]
                }
            }]
        }
        self._umbrella_client.get_api_from_app_id.return_value = broker_api

        controller.delete_tenant(self._user_info, tenant_id)

        controller.make_response.assert_called_once_with('', 204)
        self._database_controller.get_tenant.assert_called_once_with(tenant_id)

        self._keyrock_client.delete_organization.assert_called_once_with(org_id)

        self._umbrella_client.get_api_from_app_id.assert_called_once_with(self._broker_app)

        exp_api = {
            'sub_settings': [{
                'settings': {
                    'required_headers': [{
                        'key': 'Fiware-Service',
                        'value': 'new_tenant'
                    }]
                }
            }]
        }
        self._umbrella_client.update_api.assert_called_once_with(exp_api)
        self._database_controller.delete_tenant.assert_called_once_with(tenant_id)

    def test_get_users(self):
        users = {
            "users": [
                {
                    "id": "2d6f5391-6130-48d8-a9d0-01f20699a7eb",
                    "username": "alice",
                    "email": "alice@test.com",
                    "enabled": True,
                    "gravatar": False,
                    "date_password": "2018-03-20T09:31:07.000Z",
                    "description": None,
                    "website": None
                }
            ]
        }

        self._keyrock_client.get_users.return_value = users

        tenants_response = controller.get_users(self._user_info)

        self.assertEqual(tenants_response, self._response)
        controller.build_response.assert_called_once_with(users, 200)
        self._keyrock_client.get_users.assert_called_once_with()

    def test_get_users_error_connecting_keyrock(self):
        self._keyrock_client.get_users.side_effect = keyrock_client.KeyrockError("Error")

        tenants_response = controller.get_users(self._user_info)

        self.assertEqual(tenants_response, self._response)
        controller.build_response.assert_called_once_with({'error': 'Error'}, 503)
        self._keyrock_client.get_users.assert_called_once_with()

    def test_get_users_unexpected_error(self):
        self._keyrock_client.get_users.side_effect = ValueError

        self.assertRaises(ValueError, controller.get_users, self._user_info)

    def test_update_tenant(self):
        tenant_id = 'tenant_id'
        org_id = 'org_id'

        controller.request.json = [
            {'op': 'replace', 'path': '/description', 'value': 'New description'},
            {'op': 'replace', 'path': '/name', 'value': 'New name'},
            {'op': 'test', 'path': '/users/1/id', 'value': 'user_del'},
            {'op': 'test', 'path': '/users/2/id', 'value': 'user_del2'},
            {'op': 'remove', 'path': '/users/1'},
            {'op': 'remove', 'path': '/users/1'},
            {'op': 'add', 'path': '/users/-', 'value': {'id': 'user_id', 'name': 'user_name', 'roles': [self._admin_role]}},
            {'op': 'add', 'path': '/users/-', 'value': {'id': 'user_id2', 'name': 'user_name2', 'roles': [self._consumer_role]}},
            {'op': 'add', 'path': '/users/0', 'value': {'id': 'user_id3', 'name': 'user_name3', 'roles': [self._consumer_role]}}
        ]

        self._database_controller.get_tenant.return_value = {
            'id': tenant_id,
            'tenant_organization': org_id,
            'name': 'Tenant name',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': [{
                'id': 'user_id1'
            }, {
                'id': 'user_del',
                'roles': [self._admin_role]
            }, {
                'id': 'user_del2',
                'roles': [self._consumer_role]
            }]
        }

        controller.update_tenant(self._user_info, tenant_id)

        # Validate calls
        controller.make_response.assert_called_once_with('', 200)

        self._database_controller.get_tenant.assert_called_once_with(tenant_id)
        self._keyrock_client.update_organization.assert_called_once_with(org_id, {'description': 'New description', 'name': 'New name'})

        revoke_calls = self._keyrock_client.revoke_organization_role.call_args_list
        self.assertEqual([
            call(org_id, 'user_del', 'owner'),
            call(org_id, 'user_del2', 'member')
        ], revoke_calls)

        grant_calls = self._keyrock_client.grant_organization_role.call_args_list

        self.assertEqual([
            call(org_id, 'user_id3', 'member'),
            call(org_id, 'user_id', 'owner'),
            call(org_id, 'user_id2', 'member')
        ], grant_calls)

        updated_tenant = {
            'id': tenant_id,
            'tenant_organization': org_id,
            'name': 'New name',
            'owner_id': 'user-id',
            'description': 'New description',
            'users': [{
                'id': 'user_id3',
                'name': 'user_name3',
                'roles': [self._consumer_role]
            }, {
                'id': 'user_id1'
            }, {
                'id': 'user_id',
                'name': 'user_name',
                'roles': [self._admin_role]
            }, {
                'id': 'user_id2',
                'name': 'user_name2',
                'roles': [self._consumer_role]
            }]
        }
        self._database_controller.update_tenant.assert_called_once_with(tenant_id, updated_tenant)

    def _test_update_error(self, msg, code):
        response = controller.update_tenant(self._user_info, 'tenant_id')
        self.assertEqual(self._response, response)

        controller.build_response.assert_called_once_with({
            'error': msg
        }, code)

    def test_update_tenant_user_name(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'tenant_organization': 'org_id',
            'name': 'Tenant name',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': [{
                'id': 'user_id',
                'name': 'user_name'
            }]
        }

        controller.request.json = [
            {'op': 'replace', 'path': '/users/0/name', 'value': 'invalid'}
        ]

        self._test_update_error('User info cannot be modified in PATCH operation', 422)

    def test_update_tenant_remove_user_id(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'tenant_organization': 'org_id',
            'name': 'Tenant name',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': [{
                'id': 'user_id',
                'name': 'user_name'
            }]
        }

        controller.request.json = [
            {'op': 'remove', 'path': '/users/0/id'}
        ]

        self._test_update_error('Invalid user info in JSON Patch', 422)

    def test_update_tenant_unsuccess_test_op(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'tenant_organization': 'org_id',
            'name': 'Tenant name',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': []
        }

        controller.request.json = [
            {'op': 'test', 'path': '/name', 'value': 'invalid'}
        ]

        self._test_update_error('Test operation not successful', 409)

    def test_update_tenant_remove_element(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'tenant_organization': 'org_id',
            'name': 'Tenant name',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': []
        }

        controller.request.json = [
            {'op': 'remove', 'path': '/name'}
        ]

        self._test_update_error('It is not allowed to add or remove fields from tenant', 422)

    def test_update_tenant_modify_organization(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'tenant_organization': 'org_id',
            'name': 'Tenant name',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': []
        }

        controller.request.json = [
            {'op': 'replace', 'path': '/tenant_organization', 'value': 'new'}
        ]

        self._test_update_error('Tenant organization cannot be modified', 422)

    def test_update_tenant_modify_owner(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'tenant_organization': 'org_id',
            'name': 'Tenant name',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': []
        }

        controller.request.json = [
            {'op': 'replace', 'path': '/owner_id', 'value': 'new'}
        ]

        self._test_update_error('Tenant owner ID cannot be modified', 422)

    def test_update_tenant_not_exists(self):
        self._database_controller.get_tenant.return_value = None
        self._test_update_error('Tenant tenant_id does not exist', 404)

    def test_update_tenant_not_authorized(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'tenant_organization': 'org_id',
            'owner_id': 'invalid',
            'description': 'Initial description',
            'users': []
        }

        self._test_update_error('You are not authorized to delete tenant', 403)

    def test_update_tenant_invalid_format(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'tenant_organization': 'org_id',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': []
        }

        controller.request.json = [
            {'invalid': 'stuff'}
        ]

        self._test_update_error("Invalid JSON PATCH format: Operation does not contain 'op' member", 400)

    def test_update_tenant_unsupported_operation(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'name': 'Tenant name',
            'tenant_organization': 'org_id',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': []
        }

        controller.request.json = [
            {'op': 'replace', 'path': '/id', 'value': 'new_id'}
        ]

        self._test_update_error('Tenant ID cannot be modified', 422)

    def test_update_tenant_missing_value_replace(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'tenant_organization': 'org_id',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': []
        }

        controller.request.json = [
            {'op': 'replace', 'path': '/description'}
        ]

        self._test_update_error("Invalid JSON PATCH format: The operation does not contain a 'value' member", 400)

    def test_upadate_tenant_missing_value_add(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'tenant_organization': 'org_id',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': []
        }

        controller.request.json = [
            {'op': 'add', 'path': '/users/-'}
        ]

        self._test_update_error("Invalid JSON PATCH format: The operation does not contain a 'value' member", 400)

    def test_update_tenant_invalid_user(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'name': 'tenant name',
            'tenant_organization': 'org_id',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': []
        }

        controller.request.json = [
            {'op': 'add', 'path': '/users/-', 'value': 'invalid'}
        ]

        self._test_update_error('Invalid user info in JSON Patch', 422)

    def test_update_tenant_user_included(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'name': 'Tenant name',
            'tenant_organization': 'org_id',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': [{
                'id': 'user_id'
            }]
        }

        controller.request.json = [
            {'op': 'add', 'path': '/users/-', 'value': {'id': 'user_id', 'name': 'name', 'roles': []}}
        ]

        self._test_update_error('User info cannot be modified in PATCH operation', 422)

    def test_update_tenant_invalid_index_remove(self):
        self._database_controller.get_tenant.return_value = {
            'id': 'tenant_id',
            'tenant_organization': 'org_id',
            'owner_id': 'user-id',
            'description': 'Initial description',
            'users': []
        }

        controller.request.json = [
            {'op': 'remove', 'path': '/users/4'}
        ]

        self._test_update_error('Conflict applying PATCH, verify indexes and keys', 409)


if __name__ == "__main__":
    unittest.main(verbosity=2)
