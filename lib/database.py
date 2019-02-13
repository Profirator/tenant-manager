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

from pymongo import MongoClient

from bson import ObjectId


class DatabaseController:

    _db = None

    def __init__(self, host='localhost', port=27017):
        self._db = MongoClient(host, port).tenant_manager

    def save_tenant(self, tenant_id, name, description, owner, users, org_id):
        tenant_document = {
            'id': tenant_id,
            'owner_id': owner,
            'tenant_organization': org_id,
            'name': name,
            'description': description,
            'users': users
        }

        self._db.tenants.insert_one(tenant_document)

    def read_tenants(self, owner):
        def serialize_ids(t):
            del t['_id']

        return [serialize_ids(tenant) for tenant in self._db.tenants.find({'owner_id': owner})]

    def get_tenant(self, tenant_id):
        return self._db.tenants.find_one({
            'id': tenant_id
        })

    def delete_tenant(self, tenant_id):
        self._db.tenants.delete_one({
            'id': tenant_id
        })

    def update_tenant(self, tenant):
        self._db.tenants.update(tenant)
