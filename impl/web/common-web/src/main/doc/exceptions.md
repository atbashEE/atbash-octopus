* E0010

The chain name you have defined within the _securedURLs.ini_ file (or equivalent with the configuration parameter) is null. Meaning that the part before **=** was empty (assuming the developer didn't create their own syntax or that there was manual interaction with _be.atbash.ee.security.octopus.filter.mgt.FilterChainManager.addToChain(java.lang.String, java.lang.String, java.lang.String)_)

```
= user
```

* E0011

The filter name you specified in the chain was not found. Chains are defined within the _securedURLs.ini_ file (or equivalent with the configuration parameter). The second half contains the filters and one of them is not recognized.

```
/pages/** = user
/special/** = xyz
```

In the above example, xyz is not a standaard defined filter and thus when it is not specified by the developer, it is unknown to Octopus and this Exception is thrown.

* E0012

Filter configuration was specified for a Filter but the Filter doesn't accept it because it doesn't implement the _PathConfigProcessor_. All default Filters from octopus have this capability, but not all them is using it.

```
/pages/** = user, xyz[config]

```

In the example above, the xyz is a Custom defined Filter which does not implement the _PathConfigProcessor_ and hence this Exception will be thrown.



* OCT-DEV-001

Overwriting the name of the Principal (within UserPrincipal) is not allowed. (thrown by be.atbash.ee.security.octopus.subject.UserPrincipal.setName() )

* OCT-DEV-002

When the token method from the _AuthenticationInfoBuilder_ instance is called but there is already a password specified (by using the _password()_ method), this exception is raised.

_Password_ s and _token_ s can't be combined.


* OCT-DEV-003

When the password method from the _AuthenticationInfoBuilder_ instance is called but there is already a token specified (by using the _token()_ method), this exception is raised.

_Password_ s and _token_ s can't be combined.


* OCT-DEV-004

The principalId associated with a user cannot be null. specify always a non null value with the method be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder#principalId(Serializable)


* OCT-DEV-005

Exception for the use case of a type safe permission enum.

You have defined an enum with all the permissions names like

        public enum DemoPermission implements NamedPermission {
            ALL, DEPARTMENT_SALARY_ALL, DEPARTMENT_SALARY_MANAGER, DEPARTMENT_CREATE, EMPLOYEE_READ_ALL, EMPLOYEE_UPDATE_SALARY
        }

And defines the mapping to the actual permissions like this

    @ApplicationScoped
    @Produces
    public PermissionLookup<DemoPermission> buildLookup() {

        List<NamedDomainPermission> allPermissions = permissionService.getAllPermissions();
        return new PermissionLookup<DemoPermission>(allPermissions, DemoPermission.class);
    }

But the _allPermissions_ variable is an empty list which is not allowed when you want to perform a mapping as in this use case.

* OCT-DEV-006

When you as developer are creating a voter manually which is capable of verifying if the user has a certain permission, you always have to specify a non null permission instance.

    GenericPermissionVoter.createInstance(namedPermission);
    
or

    GenericPermissionVoter voter = new GenericPermissionVoter();
    voter.setNamedPermission(namedPermission)

although there are better options then doing this manually, you can't pass null as parameter or forget the _setNamedPermission()_ method call. 

* OCT-DEV-007

When you are creating a new voter manually, you can't change the permission for which the voter is checking.

    voter.setNamedPermission(namedPermission)

is not allowed when you have used _createInstance()_ to create to voter or called _setNamedPermission()_ a second time when you have instantiated the voter with _new_.
 
* OCT-DEV-008

When you as developer are creating a voter manually which is capable of verifying if the user has a certain role, you always have to specify a non null role instance.

    GenericRoleVoter.createInstance(namedRole);
    
or

    GenericRoleVoter voter = new GenericRoleVoter();
    voter.setNamedRole(namedRole)

although there are better options then doing this manually, you can't pass null as parameter or forget the _setNamedRole()_ method call. 

* OCT-DEV-007

When you are creating a new voter manually, you can't change the role for which the voter is checking.

    voter.setNamedRole(namedRole)

is not allowed when you have used _createInstance()_ to create to voter or called _setNamedRole()_ a second time when you have instantiated the voter with _new_.

* OCT-DEV-010

The name of the _ApplicationRole_ can't be empty (null or containing only spaces) when instantiating the class.

   new ApplicationRole(null);

Since the ApplicationRole is defined by his name, it is important that a correct name is specified when an instance is created. If the developer fails to do so, this exception is thrown.

* OCT-DEV-051

The subject parameter specified for the _be.atbash.ee.security.octopus.mgt.DefaultSecurityManager.logout()_ is null.

The logout should be performed by calling the _logout()_ method on _Subject_.

* OCT-DEV-101

When decoding a JWS a Key selector is required.

```
JWTDecoder.decode(data, classType);
```

Will throw this exception when the value specified for the _data_ parameters turns out to be a JWT.

* OCT-DEV-102

When creating the parameters for a JWT signing, some parameters are dependent. This error is thrown when the secretKeyType **HMAC** is specified by the secretKeySigning is NOT of type _be.atbash.ee.security.octopus.jwt.keys.HMACSecret_

 
```
JWTParametersSigning(Map<String, Object> headerValues, SecretKeyType secretKeyType, JWK secretKeySigning)
```

* OCT-DEV-103

When creating the parameters for a JWT signing, some parameters are dependent. This error is thrown when the secretKeyType **RSA** is specified by the secretKeySigning is NOT of type _com.nimbusds.jose.jwk.RSAKey_

 
```
JWTParametersSigning(Map<String, Object> headerValues, SecretKeyType secretKeyType, JWK secretKeySigning)
```

* OCT-DEV-104

When creating the parameters for a JWT signing, some parameters are dependent. This error is thrown when the secretKeyType **EC** is specified by the secretKeySigning is NOT of type _com.nimbusds.jose.jwk.ECKey_

 
```
JWTParametersSigning(Map<String, Object> headerValues, SecretKeyType secretKeyType, JWK secretKeySigning)
```

* OCT-DEV-105

When you are creating a JWT with signing (a JWS or JWE) it is required to specify the information about the secret for the signature in the parameters. This can be done by calling _withSecretKeyForSigning()_method.

```
JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS).withSecretKeyForSigning().build();
```

* OCT-DEV-106

When you are creating a JWT with encryption (a JWE) it is required to specify the information about the secret for the encryption in the parameters. This can be done by calling _withSecretKeyForEncryption()_method.

```
JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS).withSecretKeyForSigning().withSecretKeyForEncryption().build();
```
