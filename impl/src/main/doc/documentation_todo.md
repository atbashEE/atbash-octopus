
Changed 
==

* Configuration : System.getProperty("octopus.cfg") -> removed
octopusConfig.properties -> stays but environment versions allowed.


New In Atbash Octopus
==

* Better support for Micro-Services (Splitup for Web/JSF and JAX-RS)
* Better split up bewteen Authentication and Authorization (SecurityDataProvider -> AuthenticationInfoProvider)
* Multiple Authentication and Authorization sources.


Advanced
==

* Turn a Filter into a Octopus managed filter.


Expert
==

* Extends FilterChainManager to specify a custom 'syntax' for the filter definitions within securedURLs.ini file. 