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


* OCT-DEV-101

When decoding a JWS a Key selector is required.

```
JWTDecoder.decode(data, classType);
```

Will throw this exception when the value specified for the _data_ parameters turns out to be a JWT.

