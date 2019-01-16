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

VERIFY_REQUESTS = True

IDM_HOST = 'http://idm.docker:3000'
IDM_USER = 'fdelavega@conwet.com'
IDM_PASSWD = '123456789'

BROKER_APP_ID = ''
BROKER_ROLES = ['data-consumer', 'data-provider']

BAE_APP_ID = ''
BAE_ROLES = ['seller', 'customer', 'orgAdmin']


# Configure using env variables
IDM_HOST = os.environ.get('TENANT_IDM_HOST', IDM_HOST)
IDM_USER = os.environ.get('TENANT_IDM_USER', IDM_USER)
IDM_PASSWD = os.environ.get('TENANT_IDM_PASSWD', IDM_PASSWD)