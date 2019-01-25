# Opplafy Tenant Manager

[![Build Status](https://travis-ci.org/opplafy/tenant-manager.svg?branch=master)](https://travis-ci.org/opplafy/tenant-manager) [![Coverage Status](https://coveralls.io/repos/github/opplafy/tenant-manager/badge.svg?branch=master&kill_cache=1)](https://coveralls.io/github/opplafy/tenant-manager?branch=master)

This repository includes the [Opplafy](https://www.opplafy.eu/en/) 
Tenant Manager software. This service is intended to simplify the creation and 
management of tenants in a [FIWARE](https://www.fiware.org) solution using Keyrock IDM, API Umbrella, and
the Context Broker.

This service exposes an API able to orchestrate the different FIWARE
components, creating a tenant organization in Keyrock and Context 
Broker Fiware-Service read and write policies in API Umbrella.

In addition, this service configures Business API Ecosystem permissions
in order to support the monetization of NGSI data.

The Tenant manager exposes a HTTP API with the following endpoints:

**Create Tenant**

    POST http://tenantservice/tenant
    HEADERS
        Content-Type: application/json
        Authorization: Bearer [access token]
    BODY
        {
            "name": "tenant-name",
            "description": "tenant description"
        }

As a result of this request a new tenant is created, including a new organization in Keyrock IDM
and a set of policies intended to support read and write roles mapped to owner and member 
organization roles 

**Get Tenants**

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
            "description": "tenant description"
        }] 