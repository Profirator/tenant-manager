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

from urllib.parse import urlparse, urljoin

from settings import VERIFY_REQUESTS


PAGE_LEN = 100


class UmbrellaError(Exception):
    pass


class UmbrellaClient():

    _host = None
    _admin_token = None
    _api_key = None

    def __init__(self, host, admin_token, api_key):
        self._host = host
        self._admin_token = admin_token
        self._api_key = api_key

    def get_api_from_app_id(self, app_id):
        """
        Searches in API Umbrella for an API which is configured with a particular IDM app ID
        """
        # To limit the number of results, include a search by expected app_id
        url = urljoin(self._host, '/api-umbrella/v1/apis.json')

        start = 0
        processed = False
        api_elem = None

        while not processed:
            page_url = url + '?start={}&length={}'.format(start, PAGE_LEN)
            response = requests.get(page_url, headers={
                'X-Api-Key': self._api_key,
                'X-Admin-Auth-Token': self._admin_token
            }, verify=VERIFY_REQUESTS)

            if response.status_code == 401 or response.status_code == 403:
                raise UmbrellaError('Permissions error accessing API Umbrella')

            if response.status_code != 200:
                raise UmbrellaError('Error retrieving APIs from API Umbrella')

            apis = response.json()

            if not len(apis['data']):
                raise UmbrellaError('API not found in API Umbrella')

            for api in apis['data']:

                if api['settings']['idp_app_id'] == app_id:
                    processed = True
                    api_elem = api
                    break

            start += PAGE_LEN

        return api_elem

    def update_api(self, api_elem):
        url = urljoin(self._host, '/api-umbrella/v1/apis/{}'.format(api_elem['id']))

        body = {
            'api': api_elem
        }

        response = requests.put(url, headers={
            'X-Api-Key': self._api_key,
            'X-Admin-Auth-Token': self._admin_token
        }, json={'api': api_elem}, verify=VERIFY_REQUESTS)

        if response.status_code == 401 or response.status_code == 403:
            raise UmbrellaError('Permissions error accessing API Umbrella')

        if response.status_code != 204:
            raise UmbrellaError('Error adding sub setting to API')

    def add_sub_url_setting_app_id(self, app_id, sub_settings):
        """
        Appends a new sub URL setting into an API Umbrella API
        identified by IDM app ID
        """

        api_elem = self.get_api_from_app_id(app_id)
        if not 'sub_settings' in api_elem or api_elem['sub_settings'] is None:
            api_elem['sub_settings'] = []

        api_elem['sub_settings'].extend(sub_settings)
        self.update_api(api_elem)
