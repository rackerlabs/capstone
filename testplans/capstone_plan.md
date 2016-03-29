# Capstone System Test Plan

## Overview


### Background

Openstack Keystone v3 is the latest version of the Openstack authentication platform. More information can be found here:
http://specs.openstack.org/openstack/keystone-specs/api/v3/identity-api-v3.html .

DefCore is an Openstack initiative to ensure that Openstack branding is used in accordance with community goals: Additional information can be found here:
https://wiki.openstack.org/wiki/Governance/DefCoreCommittee

Capstone is an Identity stop-gap measure to ensure that we can meet the current requirements of DefCore for keystone.

Overall, we plan to approach this in two partially overlapping paths:

1. Run DefCore tempest tests against Capstone (with Rackspace Identity backend.)
2. Run integration tests to verify compatibility with Rackspace Identity v1.1 and v2.0

#### Definitions

* SUT - System Under Test


## Test Coverage

* Functional - Tests that cover user (including super type users) accessible api's in business level scenarios.
* API - Tests that focus on a single API (as much as possible)
* Performance - Tests that measure throughput and response time for a mixture of calls that approximates production usage, adjusted for the environment under test.
* Integration - Developer tests that emphasize testing multiple systems.
* Model based - Tests that emphasizes an ASM or FSM approach to modeling the SUT(s). 
* Stress - Testing at (progessively) higher levels of load inorder to determine breaking points.
* Reliability - Testing to determine MTBF.

### Functional
The initial Capstone release will not add any new functionality. It will provide a proxy between the Keystone implementation of Username/Password Authentication and the Identity Rackspace v2 implementation of Username/Password authentication.

These will most likely be implemented throught the Identity QE Ad Hoc testing code.

### API
These will be mostly the DefCore tempets tests and developer API tests.

### Performance
We will run the standard Rackspace Identity mix with an additional 10/100 RPS for Capstone. Rackspace Identity has a large amount of repeat calls, which is important since Capstone will cache authentication calls to v2. It is important to reflect that in the mix of users to Capstone authentication.

### Integration
The developers have their own tests written in python, due to the short time frame, we will use their framework, as much as possible, with additional tests done using our Ad Hoc test framework and model based tests. The focus here is on v2 compatibility.

### Model Based
We will be using model based tests to supplment, where time permits, the integration tests. These tests will focus on switching between authentication tokens issued through Capstone and directly through v2 with other v2 methods. These will have lower priority than other testing.

### Stress and Reliability
We do not have a dedicated performance testing environment, so we will not be able to perform stress or reliability testing.

## Risk Areas

* Token compatibility
* Service catalog
* Caching mechanism
* RBAC
* Keystone specific authentication mechanisms.
* Identity specific authentication mechanisms (MFA, Fed.)
* Repose V3 compatibility

### Token Compatibility
For the initial release, we only need to be concerned with v3 tokens used in v2, since v3 will only support non-token related authentication. This area is already covered by partially by the developer integration tests. Some additional coverage is needed to do basic checks against a few other v2 apis. Those can be done as part of RBAC testing.

### Service Catalog
A user should be created through vanilla create user (i.e. without a numeric domain.) and one with the one create user call.

### Caching Mechanism
It's likely Capstone will use a caching mechanism. Some testing will need to be done to verify correct behavior for dirty caches. Special attention should be made to token revocations, user updates, implicit token revocations (changing a password, enabling mfa.)

### RBAC
This testing should be around API's with different Identity RBAC rules: https://one.rackspace.com/pages/viewpage.action?title=Identity+Role+Matrix&spaceKey=auth . Testing doesn't need to be exhaustive, but a couple of different test cases around each type of rule should be sufficient.
* user admin in same domain
* user admin in different domain
* non user admin in same domain
* non user admin in different domain
* identity admin
* identity service admin

### Keystone specific authentication mechanisms.
These are covered under developer intergration testing. Some additional basic ad hoc testing should be performed.

### Identity specific authantication mechanisms.
MFA authentication should yield a reasonable error message in keystone. Similar to attempting to use v3 federated authentication.

### Repose V3 compatibility
It's not clear yet if this will be in scope for testing.


## Test Cases
### V3 tests
These are covered by the dev integration test
username/password
username/domainid/password
username/domainname/password
userid/password
username/password/domain/scope:project(tenant)
username/password/domain/scope:project(tenant),domain
username/password/domain/scope:domain

### Token Compatibility
#### Currently Covered 
V3 token, V2 validate
V2 token, V3 validate

#### To be added
V2 token, rescoping that token with V3 token authentication, with variations for scoping to project and domain
V2 mfa token, V3 token auth
V2 fed token, V3 token auth
verify auth by is returned correctly.
expires
V2 mfa scoped token in V3 auth
V2 password reset token in V3 auth
V3 token used for impersonation in V2
V2 impersonation token should be either be rejected in V3 or the impersonation bits should be ignored
  (security risk we should test for: you should not be able to get a real V3 token given a V2 impersonation token)
V3 authenticate for user with mfa enabled.
V3 auth, V2 revoke
V2 auth, V3 revoke ( 'revoke' not supported yet)
V3 auth, then v2 get role, get tenant should return same results as V2 auth then get *

### Policy
Verify V3 methods are included/excluded accroding to the policy

### Service Catalog
item by item comparison for 
nast and mosso
default region


## Caching

V3 authenticate, V2 remove mosso tenant, V3 should show updated service catalog
V3 authenticate, V2 revoke, V3 token auth should fail
V3 authenticate, V2 password update, V3 token should be revoked
V3 authenticate, V2 enable mfa, V3 token should be revoked
others indirect revokes: disable user, disable domain, maybe pick a couple.
V3 authenticate, V2 remove tenant, V3 tenant scoped authentication should fail
V3 authentication, V2 user disable (token should be revoked)

RBAC
V3 token scoped to a domain A, can't call add role to user (example) for user in domain B
