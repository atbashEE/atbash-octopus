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


