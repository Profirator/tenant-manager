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

import os
import json


VERIFY_REQUESTS = True

# Configure using env variables
IDM_URL = os.environ.get('IDM_URL', 'http://keyrock:3000')
UMBRELLA_URL = os.environ.get('UMBRELLA_URL', 'http://umbrella')

BROKER_ADMIN_ROLE = os.environ.get('BROKER_ADMIN_ROLE', 'data-provider')
BROKER_CONSUMER_ROLE = os.environ.get('BROKER_CONSUMER_ROLE', 'data-consumer')

BAE_SELLER_ROLE =  os.environ.get('BAE_SELLER_ROLE', 'seller')
BAE_CUSTOMER_ROLE =  os.environ.get('BAE_CUSTOMER_ROLE', 'customer')
BAE_ADMIN_ROLE =  os.environ.get('BAE_ADMIN_ROLE', 'orgAdmin')

BROKER_ROLES = [BROKER_ADMIN_ROLE, BROKER_CONSUMER_ROLE]
BAE_ROLES = [BAE_SELLER_ROLE, BAE_CUSTOMER_ROLE, BAE_ADMIN_ROLE]


secrets_file = "/run/secrets/{}".format(os.environ.get("CREDENTIALS_FILE", "credentials"))
if os.path.isfile(secrets_file):
    with open(secrets_file, "r") as f:
        data = json.load(f)
        BAE_APP_ID = data.get('bae', {}).get('client_id')
        BROKER_APP_ID = data.get('broker', {}).get('client_id')
        IDM_USER = data.get('idm', {}).get('user')
        IDM_PASSWD = data.get('idm', {}).get('password')
        UMBRELLA_TOKEN = data.get('umbrella', {}).get('token')
        UMBRELLA_KEY = data.get('umbrella', {}).get('key')
