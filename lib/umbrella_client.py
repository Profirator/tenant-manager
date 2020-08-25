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

import logging
logger = logging.getLogger('myapp')
hdlr = logging.FileHandler('/var/tmp/myapp.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.DEBUG)

from urllib.parse import urlparse, urljoin

from settings import VERIFY_REQUESTS


PAGE_LEN = 100

PENDING_CHANGES_ENDPOINT = "api-umbrella/v1/config/pending_changes"
PUBLISH_ENDPOINT = "api-umbrella/v1/config/publish"


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
        # api_elem = None
        api_elem = []

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
                    # api_elem = api
                    logger.debug('inside get_api_from_app_id')
                    logger.debug(api['name'])
                    api_elem.append(api)
                    # break

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

        self.publish()

    def add_sub_url_setting_app_id(self, app_id, sub_settings):
        """
        Appends a new sub URL setting into an API Umbrella API
        identified by IDM app ID
        """

        api_elem = self.get_api_from_app_id(app_id)
        print(api_elem)
        for api_elem_sg in api_elem:
            logger.debug('inside add_sub_url_setting_app_id')
            logger.debug(api_elem_sg['name'])
            if not 'sub_settings' in api_elem_sg or api_elem_sg['sub_settings'] is None:
                api_elem_sg['sub_settings'] = []

            api_elem_sg['sub_settings'].extend(sub_settings)
            self.update_api(api_elem_sg)

    def publish(self):
        headers = {
            'X-Api-Key': self._api_key,
            'X-Admin-Auth-Token': self._admin_token
        }

        # Retriveve the list of changes to be published
        url = urljoin(self._host, PENDING_CHANGES_ENDPOINT)
        response = requests.get(url, headers=headers, verify=VERIFY_REQUESTS)
        changes = response.json()

        # Prepare body for publishing the changes
        body = {
            "config": {
                "apis": {},
                "website_backends": {},
            }
        }
        for api in changes["config"]["apis"]["modified"]:
            body["config"]["apis"][api['id']] = {
                "publish": 1
            }

        url = urljoin(self._host, PUBLISH_ENDPOINT)
        response = requests.post(url, json=body, headers=headers, verify=VERIFY_REQUESTS)
        if response.status_code == 403:
            error = response.json()
            if "error" in error and "message" in error["error"]:
                raise UmbrellaError(error['error']['message'])
            else:
                raise UmbrellaError("Error publishing changes")
        elif response.status_code != 201:
            raise UmbrellaError("Error publishing changes")
