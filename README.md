# sf-keytool
Tool for generating and managing JWT certificates used for Salesforce middleware integrations.

## Purpose

sf-keytool simplifies setup and maintenance of JWT-based authentication between NAIS applications and Salesforce.

The tool provides:

* GUI for generating JWT certificates
* Validation against a Salesforce instance
* Tracking of certificate metadata and expiry
* Slack warnings before certificate expiration
* Centralized handling of middleware integration certificates

## Background

Middleware or other NAIS applications that need access to Salesforce commonly authenticate using a signed JWT certificate.

The corresponding private/public key pair is:

* configured in Salesforce
* stored as NAIS secrets in the middleware namespace

This allows middleware services to securely obtain Salesforce access tokens without interactive login.

## Typical Flow

* A Salesforce team needs a middleware application to communicate with Salesforce
* An External Client App is configured in Salesforce
* An integration user is granted access
* A JWT certificate is generated using sf-keytool
* The public certificate is uploaded to Salesforce
* The private key is stored as a NAIS secret
* Middleware authenticates using JWT Bearer flow

## Features
### Certificate Generation

Generate JWT-compatible certificate/key pairs through a GUI.

### Salesforce Verification

Test the generated configuration directly against a Salesforce instance.

### Expiry Tracking

Verified certificate configurations have their metadata stored, including expiration date

### Expiry Warnings

Slack notifications are sent before certificate expiration.

Current warning threshold:

* 90 days before expiry

## Access

Currently access is restricted to members of Platforce.

The access model may later be expanded to support self-service for Salesforce teams.
