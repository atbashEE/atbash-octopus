/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.atbash.ee.security.octopus.subject;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.realm.AuthorizingRealm;
import be.atbash.ee.security.octopus.subject.support.DefaultSubjectContext;
import be.atbash.ee.security.octopus.util.OctopusCollectionUtils;

/**
 *
 */
@ShiroEquivalent(shiroClassNames = "org.apache.shiro.subject.Subject.Builder")
public class SubjectBuilder {
    /**
     * Builder design pattern implementation for creating {@link Subject} instances in a simplified way without
     * requiring knowledge of Shiro's construction techniques.
     * <p/>
     * <b>NOTE</b>: This is provided for framework development support only and should typically never be used by
     * application developers.  {@code Subject} instances should generally be acquired by using
     * <code>SecurityUtils.{@link be.atbash.ee.security.octopus.SecurityUtils#getSubject() getSubject()}</code>
     * <h4>Usage</h4>
     * The simplest usage of this builder is to construct an anonymous, session-less {@code Subject} instance:
     * <pre>
     * Subject subject = new Subject.{@link #Builder() Builder}().{@link #buildSubject() buildSubject()};</pre>
     * The default, no-arg {@code Subject.Builder()} constructor shown above will use the application's
     * currently accessible {@code SecurityManager} via
     * <code>SecurityUtils.{@link be.atbash.ee.security.octopus.SecurityUtils#getSecurityManager() getSecurityManager()}</code>.  You may also
     * specify the exact {@code SecurityManager} instance to be used by the additional
     * <code>Subject.{@link #Builder(SecurityManager) Builder(securityManager)}</code>
     * constructor if desired.
     * <p/>
     * All other methods may be called before the {@link #buildSubject() buildSubject()} method to
     * provide context on how to construct the {@code Subject} instance.  For example, if you have a session id and
     * want to acquire the {@code Subject} that 'owns' that session (assuming the session exists and is not expired):
     * <pre>
     * Subject subject = new Subject.Builder().sessionId(sessionId).buildSubject();</pre>
     * <p/>
     * Similarly, if you want a {@code Subject} instance reflecting a certain identity:
     * <pre>
     * PrincipalCollection principals = new SimplePrincipalCollection("username", <em>yourRealmName</em>);
     * Subject subject = new Subject.Builder().principals(principals).build();</pre>
     * <p/>
     * <b>Note*</b> that the returned {@code Subject} instance is <b>not</b> automatically bound to the application (thread)
     * for further use.  That is,
     * {@link be.atbash.ee.security.octopus.SecurityUtils SecurityUtils}.{@link be.atbash.ee.security.octopus.SecurityUtils#getSubject() getSubject()}
     * will not automatically return the same instance as what is returned by the builder.  It is up to the framework
     * developer to bind the built {@code Subject} for continued use if desired.
     */
    private final SubjectContext subjectContext;

    /**
     * The SecurityManager to invoke during the {@link #buildSubject} call.
     */
    private final SubjectFactory subjectFactory;

    /**
     * Constructs a new {@link Subject.Builder} instance, using the DefaultSubjectFactory to build the {@code Subject} instance.
     */
    public SubjectBuilder(AuthorizingRealm authorizingRealm, SubjectFactory subjectFactory) {
        this.subjectFactory = subjectFactory;
        this.subjectContext = newSubjectContextInstance(authorizingRealm);
    }

    /**
     * Creates a new {@code SubjectContext} instance to be used to populate with subject contextual data that
     * will then be sent to the {@code SecurityManager} to create a new {@code Subject} instance.
     *
     * @return a new {@code SubjectContext} instance
     */
    private SubjectContext newSubjectContextInstance(AuthorizingRealm authorizingRealm) {
        return new DefaultSubjectContext(authorizingRealm);
    }

    /**
     * Returns the backing context used to build the {@code Subject} instance, available to subclasses
     * since the {@code context} class attribute is marked as {@code private}.
     *
     * @return the backing context used to build the {@code Subject} instance, available to subclasses.
     */
    protected SubjectContext getSubjectContext() {
        return this.subjectContext;
    }

    /**
     * Ensures the {@code Subject} being built will reflect the specified principals (aka identity).
     * <p/>
     * For example, if your application's unique identifier for users is a {@code String} username, and you wanted
     * to create a {@code Subject} instance that reflected a user whose username is
     * '{@code jsmith}', and you knew the Realm that could acquire {@code jsmith}'s principals based on the username
     * was named &quot;{@code myRealm}&quot;, you might create the '{@code jsmith} {@code Subject} instance this
     * way:
     * <pre>
     * PrincipalCollection identity = new {@link PrincipalCollection#PrincipalCollection(Object, String) SimplePrincipalCollection}(&quot;jsmith&quot;, &quot;myRealm&quot;);
     * Subject jsmith = new Subject.Builder().principals(identity).buildSubject();</pre>
     * <p/>
     * Similarly, if your application's unique identifier for users is a {@code long} value (such as might be used
     * as a primary key in a relational database) and you were using a {@code JDBC}
     * {@code Realm} named, (unimaginatively) &quot;jdbcRealm&quot;, you might create the Subject
     * instance this way:
     * <pre>
     * long userId = //get user ID from somewhere
     * PrincipalCollection userIdentity = new {@link PrincipalCollection#PrincipalCollection(Object, String) SimplePrincipalCollection}(<em>userId</em>, &quot;jdbcRealm&quot;);
     * Subject user = new Subject.Builder().principals(identity).buildSubject();</pre>
     *
     * @param principals the principals to use as the {@code Subject}'s identity.
     * @return this {@code Builder} instance for method chaining.
     */
    public SubjectBuilder principals(PrincipalCollection principals) {
        if (!OctopusCollectionUtils.isEmpty(principals)) {
            this.subjectContext.setPrincipals(principals);
        }
        return this;
    }

    /**
     * Ensures the {@code Subject} being built will be considered
     * {@link Subject#isAuthenticated() authenticated}.  Per the
     * {@link Subject#isAuthenticated() isAuthenticated()} JavaDoc, be careful
     * when specifying {@code true} - you should know what you are doing and have a good reason for ignoring Shiro's
     * default authentication state mechanisms.
     *
     * @param authenticated whether or not the built {@code Subject} will be considered authenticated.
     * @return this {@code Builder} instance for method chaining.
     * @see Subject#isAuthenticated()
     */
    public SubjectBuilder authenticated(boolean authenticated) {
        this.subjectContext.setAuthenticated(authenticated);
        return this;
    }

    /**
     * Creates and returns a new {@code Subject} instance reflecting the cumulative state acquired by the
     * other methods in this class.
     * <p/>
     * This {@code Builder} instance will still retain the underlying state after this method is called - it
     * will not clear it; repeated calls to this method will return multiple {@link Subject} instances, all
     * reflecting the exact same state.  If a new (different) {@code Subject} is to be constructed, a new
     * {@code Builder} instance must be created.
     * <p/>
     * <b>Note</b> that the returned {@code Subject} instance is <b>not</b> automatically bound to the application
     * (thread) for further use.  That is,
     * {@link be.atbash.ee.security.octopus.SecurityUtils SecurityUtils}.{@link be.atbash.ee.security.octopus.SecurityUtils#getSubject() getSubject()}
     * will not automatically return the same instance as what is returned by the builder.  It is up to the
     * framework developer to bind the returned {@code Subject} for continued use if desired.
     *
     * @return a new {@code Subject} instance reflecting the cumulative state acquired by the
     * other methods in this class.
     */
    public Subject buildSubject() {
        return subjectFactory.createSubject(subjectContext);
    }
}


