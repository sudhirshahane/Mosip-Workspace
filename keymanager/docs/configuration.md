# Keymanager Configuration Guide

## Overview
The guide here lists down some of the important properties that may be customised for a given installation. Note that the listing here is not exhaustive, but a checklist to review properties that are likely to be different from default.  If you would like to see all the properites, then refer to the files listed below.

## Configuration files
Keymanager uses the following configuration files:
```
application-default.properties
application-default-dmz.properties
kernel-default.properties
```

## DB
* `keymanager_database_url`
* `keymanager_database_username`
* `keymanager_database_password`

## Keystore
* `mosip.kernel.keymanager.hsm.keystore-type`
* `mosip.kernel.keymanager.hsm.config-path`
* `mosip.kernel.keymanager.hsm.keystore-pass`

## Certificate attributes
* `mosip.kernel.keymanager.certificate.default.common-name`
* `mosip.kernel.keymanager.certificate.default.organizational-unit`
* `mosip.kernel.keymanager.certificate.default.organization`
* `mosip.kernel.keymanager.certificate.default.location`
* `mosip.kernel.keymanager.certificate.default.state`
* `mosip.kernel.keymanager.certificate.default.country`

## Partner Management
* `mosip.kernel.partner.issuer.certificate.duration.years`
* `mosip.kernel.partner.issuer.certificate.allowed.grace.duration`

## JCE 
* `mosip.kernel.keymanager.hsm.jce.className`
* `mosip.kernel.keymanager.hsm.jce.keyStoreType`
* `mosip.kernel.keymanager.hsm.jce.keyStoreFile`
* `mosip.kernel.keymanager.hsm.jce.<ANY_OTHER_PARAM_01>`
* `mosip.kernel.keymanager.hsm.jce.<ANY_OTHER_PARAM_02>`