/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.mgt;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.Authorizer;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.realm.OctopusOfflineRealm;
import be.atbash.ee.security.octopus.subject.DefaultSubjectFactory;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.SubjectContext;
import be.atbash.ee.security.octopus.subject.support.DefaultSubjectContext;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Authenticator;
import java.util.Collection;
import java.util.List;

/**
 * The Shiro framework's default concrete implementation of the {@link SecurityManager} interface,
 * based around a collection of {@link org.apache.shiro.realm.Realm}s.  This implementation delegates its
 * authentication, authorization, and session operations to wrapped {@link Authenticator}, {@link Authorizer}, and
 * {@link org.apache.shiro.session.mgt.SessionManager SessionManager} instances respectively via superclass
 * implementation.
 * <p/>
 * To greatly reduce and simplify configuration, this implementation (and its superclasses) will
 * create suitable defaults for all of its required dependencies, <em>except</em> the required one or more
 * {@link Realm Realm}s.  Because {@code Realm} implementations usually interact with an application's data model,
 * they are almost always application specific;  you will want to specify at least one custom
 * {@code Realm} implementation that 'knows' about your application's data/security model
 * (via {@link #setRealm} or one of the overloaded constructors).  All other attributes in this class hierarchy
 * will have suitable defaults for most enterprise applications.
 * <p/>
 * <b>RememberMe notice</b>: This class supports the ability to configure a
 * {@link #setRememberMeManager RememberMeManager}
 * for {@code RememberMe} identity services for login/logout, BUT, a default instance <em>will not</em> be created
 * for this attribute at startup.
 * <p/>
 * Because RememberMe services are inherently client tier-specific and
 * therefore aplication-dependent, if you want {@code RememberMe} services enabled, you will have to specify an
 * instance yourself via the {@link #setRememberMeManager(RememberMeManager) setRememberMeManager}
 * mutator.  However if you're reading this JavaDoc with the
 * expectation of operating in a Web environment, take a look at the
 * {@code org.apache.shiro.web.DefaultWebSecurityManager} implementation, which
 * <em>does</em> support {@code RememberMe} services by default at startup.
 */
// No rememberMe or DAO within Java SE
@ShiroEquivalent(shiroClassNames = "org.apache.shiro.mgt.DefaultSecurityManager")
public class DefaultSecurityManager implements Authorizer {

    private static final Logger log = LoggerFactory.getLogger(DefaultSecurityManager.class);

    private DefaultSubjectFactory subjectFactory;

    private OctopusOfflineRealm octopusRealm;

    /**
     * Default no-arg constructor.
     */
    public DefaultSecurityManager() {
        super();
        this.subjectFactory = new DefaultSubjectFactory();
        this.octopusRealm = new OctopusOfflineRealm();
    }

    protected SubjectContext createSubjectContext() {
        return new DefaultSubjectContext();
    }

    /**
     * Creates a {@code Subject} instance for the user represented by the given method arguments.
     *
     * @param token    the {@code AuthenticationToken} submitted for the successful authentication.
     * @param info     the {@code AuthenticationInfo} of a newly authenticated user.
     * @param existing the existing {@code Subject} instance that initiated the authentication attempt
     * @return the {@code Subject} instance that represents the context and session data for the newly
     * authenticated subject.
     */
    protected Subject createSubject(AuthenticationToken token, AuthenticationInfo info, Subject existing) {
        SubjectContext context = createSubjectContext();
        context.setAuthenticated(true);
        context.setAuthenticationToken(token);
        context.setAuthenticationInfo(info);
        if (existing != null) {
            context.setSubject(existing);
        }
        return createSubject(context);
    }

    /**
     * First authenticates the {@code AuthenticationToken} argument, and if successful, constructs a
     * {@code Subject} instance representing the authenticated account's identity.
     * <p/>
     * Once constructed, the {@code Subject} instance is then {@link #bind bound} to the application for
     * subsequent access before being returned to the caller.
     *
     * @param token the authenticationToken to process for the login attempt.
     * @return a Subject representing the authenticated user.
     * @throws AuthenticationException if there is a problem authenticating the specified {@code token}.
     */
    public Subject login(Subject subject, AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            info = authenticate(token);
        } catch (AuthenticationException ae) {
            try {
                //onFailedLogin(token, ae, subject);  only for the rememberMe
            } catch (Exception e) {
                if (log.isInfoEnabled()) {
                    log.info("onFailedLogin method threw an " +
                            "exception.  Logging and propagating original AuthenticationException.", e);
                }
            }
            throw ae; //propagate
        }

        Subject loggedIn = createSubject(token, info, subject);

        //onSuccessfulLogin(token, info, loggedIn);  Only for the rememberMe

        return loggedIn;
    }

    /**
     * Delegates to the wrapped {@link org.apache.shiro.authc.Authenticator Authenticator} for authentication.
     */
    public AuthenticationInfo authenticate(AuthenticationToken token) throws AuthenticationException {
        return octopusRealm.authenticate(token);
    }

    protected SubjectContext copy(SubjectContext subjectContext) {
        return new DefaultSubjectContext(subjectContext);
    }

    /**
     * This implementation functions as follows:
     * <p/>
     * <ol>
     * <li>Ensures the {@code SubjectContext} is as populated as it can be, using heuristics to acquire
     * data that may not have already been available to it (such as a referenced session or remembered principals).</li>
     * <li>Calls {@link #doCreateSubject(org.apache.shiro.subject.SubjectContext)} to actually perform the
     * {@code Subject} instance creation.</li>
     * <li>calls {@link #save(org.apache.shiro.subject.Subject) save(subject)} to ensure the constructed
     * {@code Subject}'s state is accessible for future requests/invocations if necessary.</li>
     * <li>returns the constructed {@code Subject} instance.</li>
     * </ol>
     *
     * @param subjectContext any data needed to direct how the Subject should be constructed.
     * @return the {@code Subject} instance reflecting the specified contextual data.
     * @see #ensureSecurityManager(org.apache.shiro.subject.SubjectContext)
     * @see #resolveSession(org.apache.shiro.subject.SubjectContext)
     * @see #resolvePrincipals(org.apache.shiro.subject.SubjectContext)
     * @see #doCreateSubject(org.apache.shiro.subject.SubjectContext)
     * @see #save(org.apache.shiro.subject.Subject)
     * @since 1.0
     */
    public Subject createSubject(SubjectContext subjectContext) {
        //create a copy so we don't modify the argument's backing map:
        SubjectContext context = copy(subjectContext);

        //ensure that the context has a SecurityManager instance, and if not, add one:
        context = ensureSecurityManager(context);

        //Similarly, the SubjectFactory should not require any concept of RememberMe - translate that here first
        //if possible before handing off to the SubjectFactory:
        context = resolvePrincipals(context);

        return doCreateSubject(context);
    }

    /**
     * Actually creates a {@code Subject} instance by delegating to the internal
     * {@link #getSubjectFactory() subjectFactory}.  By the time this method is invoked, all possible
     * {@code SubjectContext} data (session, principals, et. al.) has been made accessible using all known heuristics
     * and will be accessible to the {@code subjectFactory} via the {@code subjectContext.resolve*} methods.
     *
     * @param context the populated context (data map) to be used by the {@code SubjectFactory} when creating a
     *                {@code Subject} instance.
     * @return a {@code Subject} instance reflecting the data in the specified {@code SubjectContext} data map.
     * @see #getSubjectFactory()
     * @see SubjectFactory#createSubject(org.apache.shiro.subject.SubjectContext)
     * @since 1.2
     */
    protected Subject doCreateSubject(SubjectContext context) {
        return subjectFactory.createSubject(context);
    }

    /**
     * Determines if there is a {@code SecurityManager} instance in the context, and if not, adds 'this' to the
     * context.  This ensures the SubjectFactory instance will have access to a SecurityManager during Subject
     * construction if necessary.
     *
     * @param context the subject context data that may contain a SecurityManager instance.
     * @return The SubjectContext to use to pass to a {@link SubjectFactory} for subject creation.
     * @since 1.0
     */
    @SuppressWarnings({"unchecked"})
    protected SubjectContext ensureSecurityManager(SubjectContext context) {
        /*
        FIXME Required ??
        if (context.resolveSecurityManager() != null) {
            log.trace("Context already contains a SecurityManager instance.  Returning.");
            return context;
        }
        log.trace("No SecurityManager found in context.  Adding self reference.");
        context.setSecurityManager(this);
        */
        return context;
    }

    /**
     * Attempts to resolve an identity (a {@link PrincipalCollection}) for the context using heuristics.  This
     * implementation functions as follows:
     * <ol>
     * <li>Check the context to see if it can already {@link SubjectContext#resolvePrincipals resolve an identity}.  If
     * so, this method does nothing and returns the method argument unaltered.</li>
     * <li>Check for a RememberMe identity by calling {@link #getRememberedIdentity}.  If that method returns a
     * non-null value, place the remembered {@link PrincipalCollection} in the context.</li>
     * </ol>
     *
     * @param context the subject context data that may provide (directly or indirectly through one of its values) a
     *                {@link PrincipalCollection} identity.
     * @return The Subject context to use to pass to a {@link SubjectFactory} for subject creation.
     * @since 1.0
     */
    @SuppressWarnings({"unchecked"})
    protected SubjectContext resolvePrincipals(SubjectContext context) {

        PrincipalCollection principals = context.resolvePrincipals();

        if (CollectionUtils.isEmpty(principals)) {
            log.trace("No identity (PrincipalCollection) found in the context.  Looking for a remembered identity.");

        }

        return context;
    }

    public void logout(Subject subject) {

        if (subject == null) {
            throw new IllegalArgumentException("Subject method argument cannot be null.");
        }

        //beforeLogout(subject); only for RememberMe

        PrincipalCollection principals = subject.getPrincipals();
        if (principals != null && !principals.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Logging out subject with primary principal {}", principals.getPrimaryPrincipal());
            }
            // FIXME TODO
            /*
            Authenticator authc = getAuthenticator();
            if (authc instanceof LogoutAware) {
                ((LogoutAware) authc).onLogout(principals);
            }
            */
        }

    }

    @Override
    public boolean isPermitted(PrincipalCollection principals, String permission) {
        return octopusRealm.isPermitted(principals, permission);
    }

    @Override
    public boolean isPermitted(PrincipalCollection subjectPrincipal, Permission permission) {
        return octopusRealm.isPermitted(subjectPrincipal, permission);
    }

    @Override
    public boolean[] isPermitted(PrincipalCollection subjectPrincipal, String... permissions) {
        return octopusRealm.isPermitted(subjectPrincipal, permissions);
    }

    @Override
    public boolean[] isPermitted(PrincipalCollection subjectPrincipal, List<Permission> permissions) {
        return octopusRealm.isPermitted(subjectPrincipal, permissions);
    }

    @Override
    public boolean isPermittedAll(PrincipalCollection subjectPrincipal, String... permissions) {
        return octopusRealm.isPermittedAll(subjectPrincipal, permissions);
    }

    @Override
    public boolean isPermittedAll(PrincipalCollection subjectPrincipal, Collection<Permission> permissions) {
        return octopusRealm.isPermittedAll(subjectPrincipal, permissions);
    }

    @Override
    public void checkPermission(PrincipalCollection subjectPrincipal, String permission) throws AuthorizationException {
        octopusRealm.checkPermission(subjectPrincipal, permission);
    }

    @Override
    public void checkPermission(PrincipalCollection subjectPrincipal, Permission permission) throws AuthorizationException {
        octopusRealm.checkPermission(subjectPrincipal, permission);
    }

    @Override
    public void checkPermissions(PrincipalCollection subjectPrincipal, String... permissions) throws AuthorizationException {
        octopusRealm.checkPermissions(subjectPrincipal, permissions);
    }

    @Override
    public void checkPermissions(PrincipalCollection subjectPrincipal, Collection<Permission> permissions) throws AuthorizationException {
        octopusRealm.checkPermissions(subjectPrincipal, permissions);
    }

    @Override
    public boolean hasRole(PrincipalCollection subjectPrincipal, String roleIdentifier) {
        return octopusRealm.hasRole(subjectPrincipal, roleIdentifier);
    }

    @Override
    public boolean[] hasRoles(PrincipalCollection subjectPrincipal, List<String> roleIdentifiers) {
        return octopusRealm.hasRoles(subjectPrincipal, roleIdentifiers);
    }

    @Override
    public boolean hasAllRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers) {
        return octopusRealm.hasAllRoles(subjectPrincipal, roleIdentifiers);
    }

    @Override
    public void checkRole(PrincipalCollection subjectPrincipal, String roleIdentifier) throws AuthorizationException {
        octopusRealm.checkRole(subjectPrincipal, roleIdentifier);
    }

    @Override
    public void checkRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers) throws AuthorizationException {
        octopusRealm.checkRoles(subjectPrincipal, roleIdentifiers);
    }

    @Override
    public void checkRoles(PrincipalCollection subjectPrincipal, String... roleIdentifiers) throws AuthorizationException {
        octopusRealm.checkRoles(subjectPrincipal, roleIdentifiers);
    }
}
