
# atbash-octopus
Declarative permission Security platform for Java EE

The Atbash Octopus is a rewrite of the original [Octopus](https://bitbucket.org/contribute-group/javaeesecurityfirst) to have the following improvements

* Better modularity (Java SE, JSF, JAX-RS, ...) for micro-services / Self-Contained systems (the original Octopus has dependency issues on for example WildFly Swarm factions)
* Integration of Apache Shiro because there were so many extensions / hacks already that it became inefficient.
* Better design since the original Octopus was designed for a certain use-case and later on heavily extended (and thus the design could be improved)

Original | Octopus 
--- | --- 
Java 6 | Java 7  
Java EE 6+ | Java EE 7+


# Work in Progress

Currently only a very small subset of the original Octopus functionality is available.

And thus for the moment, it is no valid replacement.
