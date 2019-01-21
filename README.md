# Opplafy Tenant Manager

[![Build Status](https://travis-ci.org/opplafy/tenant-manager.svg?branch=master)](https://travis-ci.org/opplafy/tenant-manager) [![Coverage Status](https://coveralls.io/repos/github/opplafy/tenant-manager/badge.svg?branch=master)](https://coveralls.io/github/opplafy/tenant-manager?branch=master)

This repository includes the [Opplafy](https://www.opplafy.eu/en/) 
Tenant Manager software. This service is intended to simplify the creation and 
management of tenants in a [FIWARE](https://www.fiware.org) solution using Keyrock IDM, API Umbrella, and
the Context Broker.

This service exposes an API able to orchestrate the different FIWARE
components, creating a tenant organization in Keyrock and Context 
Broker Fiware-Service read and write policies in API Umbrella.

In addition, this service configures Business API Ecosystem permissions
in order to support the monetization of NGSI data.
