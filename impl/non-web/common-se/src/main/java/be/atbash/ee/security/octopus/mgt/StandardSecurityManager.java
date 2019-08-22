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
package be.atbash.ee.security.octopus.mgt;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.Authenticator;
import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.Authorizer;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.realm.OctopusOfflineRealm;
import be.atbash.ee.security.octopus.subject.*;
import be.atbash.ee.security.octopus.subject.SecurityManager;
import be.atbash.ee.security.octopus.subject.support.DefaultSubjectContext;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;

/**
 * The Octopus framework's concrete implementation of the {@link SecurityManager} interface for Java SE.
 * This implementation delegates its
 * authentication, authorization, and session operations to wrapped {@link Authorizer} and {@link Authenticator} which is the realm.
 * <p/>
 */
// No rememberMe or DAO within Java SE
@ShiroEquivalent(shiroClassNames = "org.apache.shiro.mgt.DefaultSecurityManager")
public class StandardSecurityManager implements Authorizer, SecurityManager {

    private static final Logger log = LoggerFactory.getLogger(StandardSecurityManager.class);

    private SubjectFactory subjectFactory;

    private OctopusOfflineRealm octopusRealm;

    public StandardSecurityManager(SubjectFactory subjectFactory, OctopusOfflineRealm octopusRealm) {
        this.subjectFactory = subjectFactory;
        this.octopusRealm = octopusRealm;
    }

    private SubjectContext createSubjectContext() {
        return new DefaultSubjectContext(octopusRealm);
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
    private Subject createSubject(AuthenticationToken token, AuthenticationInfo info, Subject existing) {
        SubjectContext context = createSubjectContext();
        context.setAuthenticated(true);
        context.setAuthenticationToken(token);
        context.setAuthenticationInfo(info);
        context.setSecurityManager(this);
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
                // FIXME Events on Java SE
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
     * Delegates to the wrapped {@link Authenticator Authenticator} for authentication.
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
     * <li>Calls {@link #doCreateSubject(SubjectContext)} to actually perform the
     * {@code Subject} instance creation.</li>
     * <li>returns the constructed {@code Subject} instance.</li>
     * </ol>
     *
     * @param subjectContext any data needed to direct how the Subject should be constructed.
     * @return the {@code Subject} instance reflecting the specified contextual data.
     * @see #doCreateSubject(SubjectContext)
     */
    public Subject createSubject(SubjectContext subjectContext) {
        //create a copy so we don't modify the argument's backing map:
        SubjectContext context = copy(subjectContext);

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
     * @see SubjectFactory#createSubject(SubjectContext)
     */
    private Subject doCreateSubject(SubjectContext context) {
        return subjectFactory.createSubject(context);
    }

    public void logout(Subject subject) {

        if (subject == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-051) Subject method argument cannot be null.");
        }

        //beforeLogout(subject); only for RememberMe

        PrincipalCollection principals = subject.getPrincipals();
        if (principals != null && !principals.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Logging out subject with primary principal {}", principals.getPrimaryPrincipal());
            }
            octopusRealm.onLogout(principals);
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
