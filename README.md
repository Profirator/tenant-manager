# Opplafy Tenant Manager

[![Build Status](https://travis-ci.org/opplafy/tenant-manager.svg?branch=master)](https://travis-ci.org/opplafy/tenant-manager)
[![Coverage Status](https://coveralls.io/repos/github/opplafy/tenant-manager/badge.svg?branch=master&kill_cache=1)](https://coveralls.io/github/opplafy/tenant-manager?branch=master)

This repository includes the [Opplafy](https://www.opplafy.eu/en/) 
Tenant Manager software. This service is intended to simplify the creation and 
management of tenants in a [FIWARE](https://www.fiware.org) solution using Keyrock IDM, API Umbrella, and
the Context Broker.

This service exposes an API able to orchestrate the different FIWARE
components, creating a tenant organization in Keyrock and Context 
Broker FIWARE-Service read and write policies in API Umbrella.

In addition, this service configures Business API Ecosystem permissions
in order to support the monetization of NGSI data.

## How to run it

```
docker run -d --name opplafy_tenant_manager -p 5000:5000 opplafy/tenant-manager
```


## API documentation

The Tenant manager exposes a HTTP API with the following endpoints:

**Create Tenant**

    POST http://tenantservice/tenant
    HEADERS
        Content-Type: application/json
        Authorization: Bearer [access token]
    BODY
        {
            "name": "tenant-name",
            "description": "tenant description",
            "users": [{
                "name": "username",
                "roles": ["data-provider"]
            }]
        }

As a result of this request a new tenant is created, including a new organization in Keyrock IDM
and a set of policies intended to support read and write roles mapped to owner and member 
organization roles 

**Get Tenants**

This method returns all the tenants the user making the request os owner of

    GET http://tenantservice/tenant
    HEADERS
        Content-Type: application/json
        Authorization: Bearer [access token]

    RESPONSE
        [{
            "id": "tenant-id",
            "owner_id": owner,
            "tenant_organization": "org-id",
            "name": "tenant-name",
            "description": "tenant description",
            "users": [{
                "id": "user-id",
                "name": "username",
                "roles": ["data-provider"]
            }]
        }]


**Get Tenant**

This method returns a particular tenant by tenant ID if the user making the request is authorized to do so

    GET http://tenantservice/tenant/[tenant-id]
    HEADERS
        Content-Type: application/json
        Authorization: Bearer [access token]

    RESPONSE
        [{
            "id": "tenant-id",
            "owner_id": owner,
            "tenant_organization": "org-id",
            "name": "tenant-name",
            "description": "tenant description",
            "users": [{
                "id": "user-id",
                "name": "username",
                "roles": ["data-provider"]
            }]
        }]

**Get Available Users**

This method returns the available users in the IDM that can be incorporated into a tenant

    GET http://tenantservice/users
    HEADERS
        Content-Type: application/json
        Authorization: Bearer [access token]

    RESPONSE
        {
            "users": [
                {
                    "id": "2d6f5391-6130-48d8-a9d0-01f20699a7eb",
                    "username": "alice",
                    "email": "alice@test.com",
                    "enabled": true,
                    "gravatar": false,
                    "date_password": "2018-03-20T09:31:07.000Z",
                    "description": null,
                    "website": null
                }
            ]
        }