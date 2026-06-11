# ADWS LDAP Beacon Object File

This repository is for a beacon object file that allos operators to query LDAP using Active Directory Web Services (ADWS).

This is still very much a work in progress

## Usage

```
beacon> adwsldapsearch
[-] Usage:
	adwsldapsearch --ip 10.0.0.1 --domain example.com --username user --password password --query (objectClass=user) --attrs sAMAccountName,description --dn DC=lab,DC=local
	
	Arguments:
		--ip			IP address of server running ADWS, typically domain controller.
		--domain			Domain Name of the Domain you are querying.
		--username		(OPTIONAL)Username to use for authentication, use --domain to specify user domain. 
		--password		(OPTIONAL) Password to use for authentication. (OPTIONAL)
		--query			LDAP Query, CNA handles spaces in arguments, dont need to use quotes.
		--attrs			(OPTIONAL)Attributes for LDAP query, provide none to choose * 
		--dn            		Search Base for the LDAP Query 
		
	Notes:
		- Do not wrap any arguments in quotes.
		- Arguments can be placed in any order.
		- Providing no username or password will use current access token.
```


## Example Usage

#### Provided Credentials, attributes set to *

```
[06/05 17:10:53] beacon> adwsldapsearch --ip 192.168.1.100 --domain lab.local --username administrator --password nicetry --query (&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=lab,DC=local)) --dn DC=lab,DC=local
[06/05 17:10:53] [+] host called home, sent: 105470 bytes
[06/05 17:10:53] [+] received output:
[*] Object 1
  logonCount                    : 50
  codePage                      : 0
  objectCategory                : CN=Person,CN=Schema,CN=Configuration,DC=lab,DC=local
  description                   : Built-in account for administering the computer/domain
  uSNChanged                    : 69677
  instanceType                  : 4
  name                          : Administrator
  badPasswordTime               : 134243686929634297
  pwdLastSet                    : 134176712944191294
  objectClass                   : top
  objectClass                   : person
  objectClass                   : organizationalPerson
  objectClass                   : user
  badPwdCount                   : 0
  sAMAccountType                : 805306368
  lastLogonTimestamp            : 134249737202264337
  uSNCreated                    : 8196
  objectGUID                    : {4B2E7F70-8614-4EB5-88ED-BDA213DEFA50}
  memberOf                      : CN=Group Policy Creator Owners,CN=Users,DC=lab,DC=local
  memberOf                      : CN=Domain Admins,CN=Users,DC=lab,DC=local
  memberOf                      : CN=Enterprise Admins,CN=Users,DC=lab,DC=local
  memberOf                      : CN=Schema Admins,CN=Users,DC=lab,DC=local
  memberOf                      : CN=Administrators,CN=Builtin,DC=lab,DC=local
  whenCreated                   : 20260311141845.0Z
  userAccountControl            : 66048
  cn                            : Administrator
  countryCode                   : 0
  primaryGroupID                : 513
  whenChanged                   : 20260603152200.0Z
  dSCorePropagationData         : 20260311143504.0Z
  dSCorePropagationData         : 20260311143504.0Z
  dSCorePropagationData         : 20260311141954.0Z
  dSCorePropagationData         : 16010101181216.0Z
  lastLogon                     : 134249766192554339
  distinguishedName             : CN=Administrator,CN=Users,DC=lab,DC=local
  adminCount                    : 1
  isCriticalSystemObject        : TRUE
  sAMAccountName                : Administrator
  objectSid                     : S-1-5-21-1063646002-3733688200-3763894859-500
  lastLogoff                    : 0
  accountExpires                : 9223372036854775807
  container-hierarchy-parent    : 32b63b29-6ec4-4d64-9c73-da0cc9e026a6
  relativeDistinguishedName     : CN=Administrator
  distinguishedName             : CN=Administrator,CN=Users,DC=lab,DC=local

[06/05 17:10:53] [+] received output:
[*] Object 2
  logonCount                    : 44
  codePage                      : 0
  objectCategory                : CN=Person,CN=Schema,CN=Configuration,DC=lab,DC=local
  dSCorePropagationData         : 20260423165034.0Z
  dSCorePropagationData         : 16010101000000.0Z
  uSNChanged                    : 66772
  instanceType                  : 4
  name                          : domainuser1
  badPasswordTime               : 134237718550978880
  pwdLastSet                    : 134177141599763086
  objectClass                   : top
  objectClass                   : person
  objectClass                   : organizationalPerson
  objectClass                   : user
  badPwdCount                   : 0
  sAMAccountType                : 805306368
  lastLogonTimestamp            : 134246849608723280
  uSNCreated                    : 16429
  objectGUID                    : {6DEB9A5E-3ADA-4E21-93FA-5F7DB6EFAA7B}
  memberOf                      : CN=Domain Admins,CN=Users,DC=lab,DC=local
  whenCreated                   : 20260311144919.0Z
  userAccountControl            : 66048
  cn                            : domainuser1
  countryCode                   : 0
  primaryGroupID                : 513
  whenChanged                   : 20260531070920.0Z
  lastLogon                     : 134248849202713069
  distinguishedName             : CN=domainuser1,CN=Users,DC=lab,DC=local
  adminCount                    : 1
  sAMAccountName                : domainuser1
  objectSid                     : S-1-5-21-1063646002-3733688200-3763894859-1106
  lastLogoff                    : 0
  displayName                   : domainuser1
  accountExpires                : 9223372036854775807
  userPrincipalName             : domainuser1@lab.local
  container-hierarchy-parent    : 32b63b29-6ec4-4d64-9c73-da0cc9e026a6
  relativeDistinguishedName     : CN=domainuser1
  distinguishedName             : CN=domainuser1,CN=Users,DC=lab,DC=local

[06/05 17:10:53] [+] received output:
[*] Object 3
  logonCount                    : 0
  codePage                      : 0
  objectCategory                : CN=Person,CN=Schema,CN=Configuration,DC=lab,DC=local
  dSCorePropagationData         : 20260603152410.0Z
  dSCorePropagationData         : 16010101000000.0Z
  uSNChanged                    : 69679
  instanceType                  : 4
  name                          : labadmin
  badPasswordTime               : 0
  pwdLastSet                    : 134249731714679835
  objectClass                   : top
  objectClass                   : person
  objectClass                   : organizationalPerson
  objectClass                   : user
  badPwdCount                   : 0
  sAMAccountType                : 805306368
  lastLogonTimestamp            : 134249732251991876
  uSNCreated                    : 69659
  objectGUID                    : {95A0188B-C2DC-4C73-8628-EA786216A967}
  memberOf                      : CN=Domain Admins,CN=Users,DC=lab,DC=local
  whenCreated                   : 20260603151251.0Z
  userAccountControl            : 66048
  cn                            : labadmin
  countryCode                   : 0
  primaryGroupID                : 513
  whenChanged                   : 20260603152410.0Z
  lastLogon                     : 0
  distinguishedName             : CN=labadmin,CN=Users,DC=lab,DC=local
  adminCount                    : 1
  sAMAccountName                : labadmin
  objectSid                     : S-1-5-21-1063646002-3733688200-3763894859-1111
  lastLogoff                    : 0
  displayName                   : labadmin
  accountExpires                : 9223372036854775807
  userPrincipalName             : labadmin@lab.local
  container-hierarchy-parent    : 32b63b29-6ec4-4d64-9c73-da0cc9e026a6
  relativeDistinguishedName     : CN=labadmin
  distinguishedName             : CN=labadmin,CN=Users,DC=lab,DC=local
```

#### No credentials (use current access token), specify attributes

```
[06/11 09:29:03] beacon> adwsldapsearch --ip 192.168.1.100 --domain lab.local --query (&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=lab,DC=local)) --dn DC=lab,DC=local --attrs samaccountname,objectsid
[06/11 09:29:03] [+] host called home, sent: 105814 bytes
[06/11 09:29:04] [+] received output:
[*] Object 1
  objectSid                     : S-1-5-21-1063646002-3733688200-3763894859-500
  sAMAccountName                : Administrator

[06/11 09:29:04] [+] received output:
[*] Object 2
  objectSid                     : S-1-5-21-1063646002-3733688200-3763894859-1106
  sAMAccountName                : domainuser1

[06/11 09:29:04] [+] received output:
[*] Object 3
  objectSid                     : S-1-5-21-1063646002-3733688200-3763894859-1111
  sAMAccountName                : labadmin
```


## TODO

- [x] user specify dn
- [x] Authenticate with current access token
- [ ] Specify FQDN or ip
- [ ] Add feature to allow operator to specify * in attributes with other attributes (example: *,ntsecuritydescriptor)
- [ ] Look into making output better
- [ ] Create complimentary Python script to convert output into BH JSON for ingestion
- [ ] Test and implement features like configuring RBCD, etc
- [ ] Cleanup code
