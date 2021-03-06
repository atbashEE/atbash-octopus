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
import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.UnauthenticatedException;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.mgt.WebSecurityManager;
import be.atbash.ee.security.octopus.realm.AuthorizingRealm;
import be.atbash.ee.security.octopus.session.Session;
import be.atbash.ee.security.octopus.session.SessionContext;
import be.atbash.ee.security.octopus.session.SessionException;
import be.atbash.ee.security.octopus.session.mgt.DefaultSessionContext;
import be.atbash.ee.security.octopus.subject.support.DisabledSessionException;
import be.atbash.ee.security.octopus.subject.support.WebSubjectCallable;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.HostAuthenticationToken;
import be.atbash.ee.security.octopus.util.OctopusCollectionUtils;
import be.atbash.ee.security.octopus.util.RequestPairSource;
import be.atbash.util.CollectionUtils;
import be.atbash.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;

/**
 * A {@code WebSubject} represents a Subject instance that was acquired as a result of an incoming
 * {@link ServletRequest}.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.subject.WebSubject", "org.apache.shiro.web.subject.support.WebDelegatingSubject"})
// FIXME extract DelegatingSubject out of this again??
// DelegatingSubject is used for the java SE.
public class WebSubject implements RequestPairSource, Subject {

    private static final Logger log = LoggerFactory.getLogger(WebSubject.class);

    // TODO Required, Used useful?
    private static final String RUN_AS_PRINCIPALS_SESSION_KEY = WebSubject.class.getName() + ".RUN_AS_PRINCIPALS_SESSION_KEY";

    private PrincipalCollection principals;
    private boolean authenticated;
    private boolean remembered;
    private boolean fromRememberedIdentity;
    private String host;
    private Session session;
    private boolean sessionCreationEnabled;

    private transient WebSecurityManager securityManager;

    private HttpServletRequest servletRequest;
    private HttpServletResponse servletResponse;
    private AuthorizingRealm authorizingRealm;

    public WebSubject(PrincipalCollection principals, boolean authenticated, boolean remembered, boolean fromRememberedIdentity,
                      String host, Session session,
                      HttpServletRequest request, HttpServletResponse response,
                      WebSecurityManager securityManager,
                      AuthorizingRealm authorizingRealm) {
        this(principals, authenticated, remembered, fromRememberedIdentity, host, session, true, request, response, securityManager, authorizingRealm);
    }

    public WebSubject(PrincipalCollection principals, boolean authenticated, boolean remembered, boolean fromRememberedIdentity,
                      String host, Session session, boolean sessionEnabled,
                      HttpServletRequest request, HttpServletResponse response,
                      WebSecurityManager securityManager,
                      AuthorizingRealm authorizingRealm) {
        this(principals, authenticated, remembered, fromRememberedIdentity, host, session, sessionEnabled, securityManager);
        servletRequest = request;
        servletResponse = response;
        this.authorizingRealm = authorizingRealm;
    }

    public WebSubject(WebSecurityManager securityManager) {
        this(null, false, false, false, null, null, securityManager);
    }

    public WebSubject(PrincipalCollection principals, boolean authenticated, boolean remembered, boolean fromRememberedIdentity, String host,
                      Session session, WebSecurityManager securityManager) {
        this(principals, authenticated, remembered, fromRememberedIdentity, host, session, true, securityManager);
    }

    public WebSubject(PrincipalCollection principals, boolean authenticated, boolean remembered, boolean fromRememberedIdentity, String host,
                      Session session, boolean sessionCreationEnabled, WebSecurityManager securityManager) {
        if (securityManager == null) {
            throw new IllegalArgumentException("SecurityManager argument cannot be null.");
        }
        if ((authenticated || remembered) && (principals == null || principals.isEmpty())) {
            throw new IllegalArgumentException("Principal required when authenticated or remembered"); // FIXME Correct error message
        }
        this.securityManager = securityManager;
        this.principals = principals;
        this.authenticated = authenticated;
        this.remembered = remembered;
        this.fromRememberedIdentity = fromRememberedIdentity;
        this.host = host;
        if (session != null) {
            this.session = decorate(session);
        }
        this.sessionCreationEnabled = sessionCreationEnabled;
    }

    protected Session decorate(Session session) {
        if (session == null) {
            throw new IllegalArgumentException("session cannot be null");
        }
        // FIXME Find out why we need to know when session is stopped?
        //return new StoppingAwareProxiedSession(session, this);
        return session;
    }

    protected boolean hasPrincipals() {
        return !OctopusCollectionUtils.isEmpty(getPrincipals());
    }

    /**
     * Returns the host name or IP associated with the client who created/is interacting with this Subject.
     *
     * @return the host name or IP associated with the client who created/is interacting with this Subject.
     */
    public String getHost() {
        return host;
    }

    private UserPrincipal getPrimaryPrincipal(PrincipalCollection principals) {
        if (!OctopusCollectionUtils.isEmpty(principals)) {
            return principals.getPrimaryPrincipal();
        }
        // FIXME Is this possible ??
        return null;
    }

    /**
     * Returns this Subject's application-wide uniquely identifying principal, or {@code null} if this
     * Subject is anonymous because it doesn't yet have any associated account data (for example,
     * if they haven't logged in).
     * <p/>
     * The term <em>principal</em> is just a fancy security term for any identifying attribute(s) of an application
     * user, such as a username, or user id, or public key, or anything else you might use in your application to
     * identify a user.
     * <h4>Uniqueness</h4>
     * Although given names and family names (first/last) are technically considered principals as well,
     * Shiro expects the object returned from this method to be an identifying attribute unique across
     * your entire application.
     * <p/>
     * This implies that things like given names and family names are usually poor
     * candidates as return values since they are rarely guaranteed to be unique;  Things often used for this value:
     * <ul>
     * <li>A {@code long} RDBMS surrogate primary key</li>
     * <li>An application-unique username</li>
     * <li>A {@link java.util.UUID UUID}</li>
     * <li>An LDAP Unique ID</li>
     * </ul>
     * or any other similar suitable unique mechanism valuable to your application.
     * <p/>
     * Most implementations will simply return
     * <code>{@link #getPrincipals()}.{@link PrincipalCollection#getPrimaryPrincipal() getPrimaryPrincipal()}</code>
     *
     * @return this Subject's application-specific unique identity.
     * @see PrincipalCollection#getPrimaryPrincipal()
     */
    public UserPrincipal getPrincipal() {
        // ToDO update rest of methods so that we always have a primaryPrincipal (never null)
        return getPrimaryPrincipal(getPrincipals());
    }

    /**
     * Returns this Subject's principals (identifying attributes) in the form of a {@code PrincipalCollection} or
     * {@code null} if this Subject is anonymous because it doesn't yet have any associated account data (for example,
     * if they haven't logged in).
     * <p/>
     * The word &quot;principals&quot; is nothing more than a fancy security term for identifying attributes associated
     * with a Subject, aka, application user.  For example, user id, a surname (family/last name), given (first) name,
     * social security number, nickname, username, etc, are all examples of a principal.
     *
     * @return all of this Subject's principals (identifying attributes).
     * @see #getPrincipal()
     * @see PrincipalCollection#getPrimaryPrincipal()
     */
    public PrincipalCollection getPrincipals() {
        List<PrincipalCollection> runAsPrincipals = getRunAsPrincipalsStack();
        return CollectionUtils.isEmpty(runAsPrincipals) ? principals : runAsPrincipals.get(0);
    }

    /**
     * Returns {@code true} if this Subject is permitted to perform an action or access a resource summarized by the
     * specified permission string.
     * <p/>
     * This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permission the String representation of a Permission that is being checked.
     * @return true if this Subject is permitted, false otherwise.
     * @see #isPermitted(Permission permission)
     */
    public boolean isPermitted(String permission) {
        return hasPrincipals() && securityManager.isPermitted(getPrincipals(), permission);
    }

    /**
     * Returns {@code true} if this Subject is permitted to perform an action or access a resource summarized by the
     * specified permission.
     * <p/>
     * More specifically, this method determines if any {@code Permission}s associated
     * with the subject {@link Permission#implies(Permission) imply} the specified permission.
     *
     * @param permission the permission that is being checked.
     * @return true if this Subject is permitted, false otherwise.
     */
    public boolean isPermitted(Permission permission) {
        return hasPrincipals() && securityManager.isPermitted(getPrincipals(), permission);
    }

    /**
     * Checks if this Subject implies the given permission strings and returns a boolean array indicating which
     * permissions are implied.
     * <p/>
     * This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permissions the String representations of the Permissions that are being checked.
     * @return a boolean array where indices correspond to the index of the
     * permissions in the given list.  A true value at an index indicates this Subject is permitted for
     * for the associated {@code Permission} string in the list.  A false value at an index
     * indicates otherwise.
     */
    public boolean[] isPermitted(String... permissions) {
        if (hasPrincipals()) {
            return securityManager.isPermitted(getPrincipals(), permissions);
        } else {
            return new boolean[permissions.length];
        }
    }

    /**
     * Checks if this Subject implies the given Permissions and returns a boolean array indicating which permissions
     * are implied.
     * <p/>
     * More specifically, this method should determine if each {@code Permission} in
     * the array is {@link Permission#implies(Permission) implied} by permissions
     * already associated with the subject.
     * <p/>
     * This is primarily a performance-enhancing method to help reduce the number of
     * {@link #isPermitted} invocations over the wire in client/server systems.
     *
     * @param permissions the permissions that are being checked.
     * @return a boolean array where indices correspond to the index of the
     * permissions in the given list.  A true value at an index indicates this Subject is permitted for
     * for the associated {@code Permission} object in the list.  A false value at an index
     * indicates otherwise.
     */
    public boolean[] isPermitted(List<Permission> permissions) {
        if (hasPrincipals()) {
            return securityManager.isPermitted(getPrincipals(), permissions);
        } else {
            return new boolean[permissions.size()];
        }
    }

    /**
     * Returns {@code true} if this Subject implies all of the specified permission strings, {@code false} otherwise.
     * <p/>
     * This is an overloaded method for the corresponding type-safe {@link Permission Permission}
     * variant.  Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permissions the String representations of the Permissions that are being checked.
     * @return true if this Subject has all of the specified permissions, false otherwise.
     * @see #isPermittedAll(Collection)
     */
    public boolean isPermittedAll(String... permissions) {
        return hasPrincipals() && securityManager.isPermittedAll(getPrincipals(), permissions);
    }

    /**
     * Returns {@code true} if this Subject implies all of the specified permissions, {@code false} otherwise.
     * <p/>
     * More specifically, this method determines if all of the given {@code Permission}s are
     * {@link Permission#implies(Permission) implied by} permissions already associated with this Subject.
     *
     * @param permissions the permissions to check.
     * @return true if this Subject has all of the specified permissions, false otherwise.
     */
    public boolean isPermittedAll(Collection<Permission> permissions) {
        return hasPrincipals() && securityManager.isPermittedAll(getPrincipals(), permissions);
    }

    protected void assertAuthzCheckPossible() throws AuthorizationException {
        if (!hasPrincipals()) {
            String msg = "This subject is anonymous - it does not have any identifying principals and " +
                    "authorization operations require an identity to check against.  A Subject instance will " +
                    "acquire these identifying principals automatically after a successful login is performed " +
                    "be executing " + WebSubject.class.getName() + ".login(AuthenticationToken) or when 'Remember Me' " +
                    "functionality is enabled by the SecurityManager.  This exception can also occur when a " +
                    "previously logged-in Subject has logged out which " +
                    "makes it anonymous again.  Because an identity is currently not known due to any of these " +
                    "conditions, authorization is denied.";
            throw new UnauthenticatedException(msg);
        }
    }

    /**
     * Ensures this Subject implies the specified permission String.
     * <p/>
     * If this subject's existing associated permissions do not {@link Permission#implies(Permission)} imply}
     * the given permission, an {@link AuthorizationException} will be thrown.
     * <p/>
     * This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permission the String representation of the Permission to check.
     * @throws AuthorizationException if the user does not have the permission.
     */
    public void checkPermission(String permission) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermission(getPrincipals(), permission);
    }

    /**
     * Ensures this Subject {@link Permission#implies(Permission) implies} the specified {@code Permission}.
     * <p/>
     * If this subject's existing associated permissions do not {@link Permission#implies(Permission) imply}
     * the given permission, an {@link AuthorizationException} will be thrown.
     *
     * @param permission the Permission to check.
     * @throws AuthorizationException if this Subject does not have the permission.
     */
    public void checkPermission(Permission permission) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermission(getPrincipals(), permission);
    }

    /**
     * Ensures this Subject
     * {@link Permission#implies(Permission) implies} all of the
     * specified permission strings.
     * <p/>
     * If this subject's existing associated permissions do not
     * {@link Permission#implies(Permission) imply} all of the given permissions,
     * an {@link AuthorizationException} will be thrown.
     * <p/>
     * This is an overloaded method for the corresponding type-safe {@link Permission Permission} variant.
     * Please see the class-level JavaDoc for more information on these String-based permission methods.
     *
     * @param permissions the string representations of Permissions to check.
     * @throws AuthorizationException if this Subject does not have all of the given permissions.
     */
    public void checkPermissions(String... permissions) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermissions(getPrincipals(), permissions);
    }

    /**
     * Ensures this Subject
     * {@link Permission#implies(Permission) implies} all of the
     * specified permission strings.
     * <p/>
     * If this subject's existing associated permissions do not
     * {@link Permission#implies(Permission) imply} all of the given permissions,
     * an {@link AuthorizationException} will be thrown.
     *
     * @param permissions the Permissions to check.
     * @throws AuthorizationException if this Subject does not have all of the given permissions.
     */
    public void checkPermissions(Collection<Permission> permissions) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermissions(getPrincipals(), permissions);
    }

    /**
     * Returns {@code true} if this Subject has the specified role, {@code false} otherwise.
     *
     * @param roleIdentifier the application-specific role identifier (usually a role id or role name).
     * @return {@code true} if this Subject has the specified role, {@code false} otherwise.
     */
    public boolean hasRole(String roleIdentifier) {
        return hasPrincipals() && securityManager.hasRole(getPrincipals(), roleIdentifier);
    }

    /**
     * Checks if this Subject has the specified roles, returning a boolean array indicating
     * which roles are associated.
     * <p/>
     * This is primarily a performance-enhancing method to help reduce the number of
     * {@link #hasRole} invocations over the wire in client/server systems.
     *
     * @param roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @return a boolean array where indices correspond to the index of the
     * roles in the given identifiers.  A true value indicates this Subject has the
     * role at that index.  False indicates this Subject does not have the role at that index.
     */
    public boolean[] hasRoles(List<String> roleIdentifiers) {
        if (hasPrincipals()) {
            return securityManager.hasRoles(getPrincipals(), roleIdentifiers);
        } else {
            return new boolean[roleIdentifiers.size()];
        }
    }

    /**
     * Returns {@code true} if this Subject has all of the specified roles, {@code false} otherwise.
     *
     * @param roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @return true if this Subject has all the roles, false otherwise.
     */
    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        return hasPrincipals() && securityManager.hasAllRoles(getPrincipals(), roleIdentifiers);
    }

    /**
     * Asserts this Subject has the specified role by returning quietly if they do or throwing an
     * {@link AuthorizationException} if they do not.
     *
     * @param role the application-specific role identifier (usually a role id or role name ).
     * @throws AuthorizationException if this Subject does not have the role.
     */
    public void checkRole(String role) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkRole(getPrincipals(), role);
    }

    /**
     * Same as {@link #checkRoles(Collection < String > role) checkRoles(Collection<String> roleIdentifiers)} but
     * doesn't require a collection as a an argument.
     * Asserts this Subject has all of the specified roles by returning quietly if they do or throwing an
     * {@link AuthorizationException} if they do not.
     *
     * @param roles roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @throws AuthorizationException AuthorizationException
     *                                if this Subject does not have all of the specified roles.
     */
    public void checkRoles(String... roles) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkRoles(getPrincipals(), roles);
    }

    /**
     * Asserts this Subject has all of the specified roles by returning quietly if they do or throwing an
     * {@link AuthorizationException} if they do not.
     *
     * @param roles the application-specific role identifiers to check (usually role ids or role names).
     * @throws AuthorizationException if this Subject does not have all of the specified roles.
     */
    public void checkRoles(Collection<String> roles) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkRoles(getPrincipals(), roles);
    }

    /**
     * Returns {@code true} if this Subject/user proved their identity <em>during their current session</em>
     * by providing valid credentials matching those known to the system, {@code false} otherwise.
     * <p/>
     * Note that even if this Subject's identity has been remembered via 'remember me' services, this method will
     * still return {@code false} unless the user has actually logged in with proper credentials <em>during their
     * current session</em>.  See the {@link #isRemembered() isRemembered()} method JavaDoc for more.
     *
     * @return {@code true} if this Subject proved their identity during their current session
     * by providing valid credentials matching those known to the system, {@code false} otherwise.
     */
    public boolean isAuthenticated() {
        PrincipalCollection principals = getPrincipals();
        return principals != null && !principals.isEmpty() && authenticated;

    }

    /**
     * Returns {@code true} if this {@code Subject} has an identity (it is not anonymous) and the identity
     * (aka {@link #getPrincipals() principals}) is remembered from a successful authentication during a previous
     * session.
     * <p/>
     * Although the underlying implementation determines exactly how this method functions, most implementations have
     * this method act as the logical equivalent to this code:
     * <pre>
     * {@link #getPrincipal() getPrincipal()} != null && !{@link #isAuthenticated() isAuthenticated()}</pre>
     * <p/>
     * Note as indicated by the above code example, if a {@code Subject} is remembered, they are
     * <em>NOT</em> considered authenticated.  A check against {@link #isAuthenticated() isAuthenticated()} is a more
     * strict check than that reflected by this method.  For example, a check to see if a subject can access financial
     * information should almost always depend on {@link #isAuthenticated() isAuthenticated()} to <em>guarantee</em> a
     * verified identity, and not this method.
     * <p/>
     * Once the subject is authenticated, they are no longer considered only remembered because their identity would
     * have been verified during the current session.
     * <h4>Remembered vs Authenticated</h4>
     * Authentication is the process of <em>proving</em> you are who you say you are.  When a user is only remembered,
     * the remembered identity gives the system an idea who that user probably is, but in reality, has no way of
     * absolutely <em>guaranteeing</em> if the remembered {@code Subject} represents the user currently
     * using the application.
     * <p/>
     * So although many parts of the application can still perform user-specific logic based on the remembered
     * {@link #getPrincipals() principals}, such as customized views, it should never perform highly-sensitive
     * operations until the user has legitimately verified their identity by executing a successful authentication
     * attempt.
     * <p/>
     * We see this paradigm all over the web, and we will use <a href="http://www.amazon.com">Amazon.com</a> as an
     * example:
     * <p/>
     * When you visit Amazon.com and perform a login and ask it to 'remember me', it will set a cookie with your
     * identity.  If you don't log out and your session expires, and you come back, say the next day, Amazon still knows
     * who you <em>probably</em> are: you still see all of your book and movie recommendations and similar user-specific
     * features since these are based on your (remembered) user id.
     * <p/>
     * BUT, if you try to do something sensitive, such as access your account's billing data, Amazon forces you
     * to do an actual log-in, requiring your username and password.
     * <p/>
     * This is because although amazon.com assumed your identity from 'remember me', it recognized that you were not
     * actually authenticated.  The only way to really guarantee you are who you say you are, and therefore allow you
     * access to sensitive account data, is to force you to perform an actual successful authentication.  You can
     * check this guarantee via the {@link #isAuthenticated() isAuthenticated()} method and not via this method.
     *
     * @return {@code true} if this {@code Subject}'s identity (aka {@link #getPrincipals() principals}) is
     * remembered from a successful authentication during a previous session, {@code false} otherwise.
     */
    public boolean isRemembered() {
        PrincipalCollection principals = getPrincipals();
        return principals != null && !principals.isEmpty() && remembered;
    }

    /**
     * Is this Subject created from a Remembered Identify directly.
     *
     * @return
     */
    public boolean isFromRememberedIdentity() {
        return fromRememberedIdentity;
    }

    /**
     * Returns {@code true} if this Subject is allowed to create sessions, {@code false} otherwise.
     *
     * @return {@code true} if this Subject is allowed to create sessions, {@code false} otherwise.
     */
    protected boolean isSessionCreationEnabled() {
        return sessionCreationEnabled;
    }

    /**
     * Returns the application {@code Session} associated with this Subject.  If no session exists when this
     * method is called, a new session will be created, associated with this Subject, and then returned.
     *
     * @return the application {@code Session} associated with this Subject.
     * @see #getSession(boolean)
     */
    public Session getSession() {
        return getSession(true);
    }

    /**
     * Returns the application {@code Session} associated with this Subject.  Based on the boolean argument,
     * this method functions as follows:
     * <ul>
     * <li>If there is already an existing session associated with this {@code Subject}, it is returned and
     * the {@code create} argument is ignored.</li>
     * <li>If no session exists and {@code create} is {@code true}, a new session will be created, associated with
     * this {@code Subject} and then returned.</li>
     * <li>If no session exists and {@code create} is {@code false}, {@code null} is returned.</li>
     * </ul>
     *
     * @param create boolean argument determining if a new session should be created or not if there is no existing session.
     * @return the application {@code Session} associated with this {@code Subject} or {@code null} based
     * on the above described logic.
     */
    public Session getSession(boolean create) {
        if (log.isTraceEnabled()) {
            log.trace("attempting to get session; create = " + create +
                    "; session is null = " + (session == null) +
                    "; session has id = " + (session != null && session.getId() != null));
        }

        if (session == null && create) {

            //added in 1.2:
            if (!isSessionCreationEnabled()) {
                String msg = "Session creation has been disabled for the current subject.  This exception indicates " +
                        "that there is either a programming error (using a session when it should never be " +
                        "used) or that Shiro's configuration needs to be adjusted to allow Sessions to be created " +
                        "for the current Subject.  See the " + DisabledSessionException.class.getName() + " JavaDoc " +
                        "for more.";
                throw new DisabledSessionException(msg);
            }

            log.trace("Starting session for host {}", getHost());
            SessionContext sessionContext = createSessionContext();
            Session session = securityManager.start(sessionContext);
            this.session = decorate(session);
        }
        return this.session;
    }

    protected SessionContext createSessionContext() {
        SessionContext sessionContext = new DefaultSessionContext();
        if (StringUtils.hasText(host)) {
            sessionContext.setHost(host);
        }
        sessionContext.setServletRequest(getServletRequest());
        sessionContext.setServletResponse(getServletResponse());
        return sessionContext;
    }

    private void clearRunAsIdentitiesInternal() {
        //try/catch added for SHIRO-298
        try {
            clearRunAsIdentities();
        } catch (SessionException se) {
            log.debug("Encountered session exception trying to clear 'runAs' identities during logout.  This " +
                    "can generally safely be ignored.", se);
        }
    }

    /**
     * Logs out this Subject and invalidates and/or removes any associated entities,
     * such as a {@link Session Session} and authorization data.  After this method is called, the Subject is
     * considered 'anonymous' and may continue to be used for another log-in if desired.
     * <h3>Web Environment Warning</h3>
     * Calling this method in web environments will usually remove any associated session cookie as part of
     * session invalidation.  Because cookies are part of the HTTP header, and headers can only be set before the
     * response body (html, image, etc) is sent, this method in web environments must be called before <em>any</em>
     * content has been rendered.
     * <p/>
     * The typical approach most applications use in this scenario is to redirect the user to a different
     * location (e.g. home page) immediately after calling this method.  This is an effect of the HTTP protocol
     * itself and not a reflection of Shiro's implementation.
     * <p/>
     * Non-HTTP environments may of course use a logged-out subject for login again if desired.
     */
    public void logout() {
        try {
            clearRunAsIdentitiesInternal();
            securityManager.logout(this);
        } finally {
            session = null;
            principals = null;
            authenticated = false;
            remembered = false;
            //Don't set securityManager to null here - the Subject can still be
            //used, it is just considered anonymous at this point.  The SecurityManager instance is
            //necessary if the subject would log in again or acquire a new session.  This is in response to
            //https://issues.apache.org/jira/browse/JSEC-22
            //this.securityManager = null;
        }
    }

    private void sessionStopped() {
        session = null;
    }

    /**
     * Associates the specified {@code Callable} with this {@code Subject} instance and then executes it on the
     * currently running thread.  If you want to execute the {@code Callable} on a different thread, it is better to
     * use the {@link #associateWith(Callable)} method instead.
     *
     * @param callable the Callable to associate with this subject and then execute.
     * @param <V>      the type of return value the {@code Callable} will return
     * @return the resulting object returned by the {@code Callable}'s execution.
     * @throws ExecutionException if the {@code Callable}'s {@link Callable#call call} method throws an exception.
     */
    public <V> V execute(Callable<V> callable) throws ExecutionException {
        Callable<V> associated = associateWith(callable);
        try {
            return associated.call();
        } catch (Throwable t) {
            throw new ExecutionException(t);
        }
    }

    /**
     * Associates the specified {@code Runnable} with this {@code Subject} instance and then executes it on the
     * currently running thread.  If you want to execute the {@code Runnable} on a different thread, it is better to
     * use the {@link #associateWith(Runnable)} method instead.
     * <p/>
     * <b>Note</b>: This method is primarily provided to execute existing/legacy Runnable implementations.  It is better
     * for new code to use {@link #execute(Callable)} since that supports the ability to return values and catch
     * exceptions.
     *
     * @param runnable the {@code Runnable} to associate with this {@code Subject} and then execute.
     */
    public void execute(Runnable runnable) {
        Runnable associated = associateWith(runnable);
        associated.run();
    }

    /**
     * Returns a {@code Callable} instance matching the given argument while additionally ensuring that it will
     * retain and execute under this Subject's identity.  The returned object can be used with an
     * {@link java.util.concurrent.ExecutorService ExecutorService} to execute as this Subject.
     * <p/>
     * This will effectively ensure that any calls to
     * {@code SecurityUtils}.{@link WebSecurityUtils#getSubject() getSubject()} and related functionality will continue
     * to function properly on any thread that executes the returned {@code Callable} instance.
     *
     * @param callable the callable to execute as this {@code Subject}
     * @param <V>      the {@code Callable}s return value type
     * @return a {@code Callable} that can be run as this {@code Subject}.
     */
    public <V> Callable<V> associateWith(Callable<V> callable) {

        return new WebSubjectCallable<>(this, callable);
    }

    /**
     * Returns a {@code Runnable} instance matching the given argument while additionally ensuring that it will
     * retain and execute under this Subject's identity.  The returned object can be used with an
     * {@link java.util.concurrent.Executor Executor} or another thread to execute as this Subject.
     * <p/>
     * This will effectively ensure that any calls to
     * {@code SecurityUtils}.{@link WebSecurityUtils#getSubject() getSubject()} and related functionality will continue
     * to function properly on any thread that executes the returned {@code Runnable} instance.
     * <p/>
     * *Note that if you need a return value to be returned as a result of the runnable's execution or if you need to
     * react to any Exceptions, it is highly recommended to use the
     * {@link #associateWith(java.util.concurrent.Callable) createCallable} method instead of this one.
     *
     * @param runnable the runnable to execute as this {@code Subject}
     * @return a {@code Runnable} that can be run as this {@code Subject} on another thread.
     * @see #associateWith (java.util.concurrent.Callable)
     */
    public Runnable associateWith(Runnable runnable) {
        if (runnable instanceof Thread) {
            String msg = "This implementation does not support Thread arguments because of JDK ThreadLocal " +
                    "inheritance mechanisms required by Shiro.  Instead, the method argument should be a non-Thread " +
                    "Runnable and the return value from this method can then be given to an ExecutorService or " +
                    "another Thread.";
            throw new UnsupportedOperationException(msg);
        }
        // FIXME
        throw new UnsupportedOperationException("Not implemented be.atbash.ee.security.octopus.subject.WebSubject.associateWith(java.lang.Runnable)");

        //return new SubjectRunnable(this, runnable);
    }

    // ======================================
    // 'Run As' support implementations
    // ======================================

    /**
     * Allows this subject to 'run as' or 'assume' another identity indefinitely.  This can only be
     * called when the {@code Subject} instance already has an identity (i.e. they are remembered from a previous
     * log-in or they have authenticated during their current session).
     * <p/>
     * Some notes about {@code runAs}:
     * <ul>
     * <li>You can tell if a {@code Subject} is 'running as' another identity by calling the
     * {@link #isRunAs() isRunAs()} method.</li>
     * <li>If running as another identity, you can determine what the previous 'pre run as' identity
     * was by calling the {@link #getPreviousPrincipals() getPreviousPrincipals()} method.</li>
     * <li>When you want a {@code Subject} to stop running as another identity, you can return to its previous
     * 'pre run as' identity by calling the {@link #releaseRunAs() releaseRunAs()} method.</li>
     * </ul>
     *
     * @param principals the identity to 'run as', aka the identity to <em>assume</em> indefinitely.
     * @throws NullPointerException  if the specified principals collection is {@code null} or empty.
     * @throws IllegalStateException if this {@code Subject} does not yet have an identity of its own.
     */
    public void runAs(PrincipalCollection principals) throws NullPointerException, IllegalStateException {
        if (!hasPrincipals()) {
            String msg = "This subject does not yet have an identity.  Assuming the identity of another " +
                    "Subject is only allowed for Subjects with an existing identity.";
            throw new IllegalStateException(msg);
        }
        pushIdentity(principals);
    }

    /**
     * Returns {@code true} if this {@code Subject} is 'running as' another identity other than its original one or
     * {@code false} otherwise (normal {@code Subject} state).  See the {@link #runAs runAs} method for more
     * information.
     *
     * @return {@code true} if this {@code Subject} is 'running as' another identity other than its original one or
     * {@code false} otherwise (normal {@code Subject} state).
     * @see #runAs
     */
    public boolean isRunAs() {
        List<PrincipalCollection> stack = getRunAsPrincipalsStack();
        return !CollectionUtils.isEmpty(stack);
    }

    /**
     * Returns the previous 'pre run as' identity of this {@code Subject} before assuming the current
     * {@link #runAs runAs} identity, or {@code null} if this {@code Subject} is not operating under an assumed
     * identity (normal state). See the {@link #runAs runAs} method for more information.
     *
     * @return the previous 'pre run as' identity of this {@code Subject} before assuming the current
     * {@link #runAs runAs} identity, or {@code null} if this {@code Subject} is not operating under an assumed
     * identity (normal state).
     * @see #runAs
     */
    public PrincipalCollection getPreviousPrincipals() {
        PrincipalCollection previousPrincipals = null;
        List<PrincipalCollection> stack = getRunAsPrincipalsStack();
        int stackSize = stack != null ? stack.size() : 0;
        if (stackSize > 0) {
            if (stackSize == 1) {
                previousPrincipals = principals;
            } else {
                //always get the one behind the current:
                assert stack != null;
                previousPrincipals = stack.get(1);
            }
        }
        return previousPrincipals;
    }

    /**
     * Releases the current 'run as' (assumed) identity and reverts back to the previous 'pre run as'
     * identity that existed before {@code #runAs runAs} was called.
     * <p/>
     * This method returne 'run as' (assumed) identity being released or {@code null} if this {@code Subject} is not
     * operating under an assumed identity.
     *
     * @return the 'run as' (assumed) identity being released or {@code null} if this {@code Subject} is not operating
     * under an assumed identity.
     * @see #runAs
     */
    public PrincipalCollection releaseRunAs() {
        return popIdentity();
    }

    @SuppressWarnings("unchecked")
    private List<PrincipalCollection> getRunAsPrincipalsStack() {
        Session session = getSession(false);
        if (session != null) {
            return (List<PrincipalCollection>) session.getAttribute(RUN_AS_PRINCIPALS_SESSION_KEY);
        }
        return null;
    }

    private void clearRunAsIdentities() {
        Session session = getSession(false);
        if (session != null) {
            session.removeAttribute(RUN_AS_PRINCIPALS_SESSION_KEY);
        }
    }

    private void pushIdentity(PrincipalCollection principals) throws NullPointerException {
        if (OctopusCollectionUtils.isEmpty(principals)) {
            String msg = "Specified Subject principals cannot be null or empty for 'run as' functionality.";
            throw new NullPointerException(msg);
        }
        List<PrincipalCollection> stack = getRunAsPrincipalsStack();
        if (stack == null) {
            stack = new CopyOnWriteArrayList<>();
        }
        stack.add(0, principals);
        Session session = getSession();
        session.setAttribute(RUN_AS_PRINCIPALS_SESSION_KEY, stack);
    }

    private PrincipalCollection popIdentity() {
        PrincipalCollection popped = null;

        List<PrincipalCollection> stack = getRunAsPrincipalsStack();
        if (!CollectionUtils.isEmpty(stack)) {
            popped = stack.remove(0);
            Session session;
            if (!CollectionUtils.isEmpty(stack)) {
                //persist the changed stack to the session
                session = getSession();
                session.setAttribute(RUN_AS_PRINCIPALS_SESSION_KEY, stack);
            } else {
                //stack is empty, remove it from the session:
                clearRunAsIdentities();
            }
        }

        return popped;
    }

    public WebSecurityManager getSecurityManager() {
        return securityManager;
    }

    /**
     * Returns the {@code ServletRequest} accessible when the Subject instance was created.
     *
     * @return the {@code ServletRequest} accessible when the Subject instance was created.
     */
    public HttpServletRequest getServletRequest() {
        return servletRequest;
    }

    /**
     * Returns the {@code ServletResponse} accessible when the Subject instance was created.
     *
     * @return the {@code ServletResponse} accessible when the Subject instance was created.
     */
    public HttpServletResponse getServletResponse() {
        return servletResponse;
    }

    public void login(AuthenticationToken token) {
        clearRunAsIdentitiesInternal();
        WebSubject subject = securityManager.login(this, token);

        PrincipalCollection principals;

        String host = null;

        /*
        FIXME Needed
        if (subject instanceof DelegatingSubject) {
            DelegatingSubject delegating = (DelegatingSubject) subject;
            //we have to do this in case there are assumed identities - we don't want to lose the 'real' principals:
            principals = delegating.getPrincipals();
            host = delegating.getHost();
        } else {

              principals = subject.getPrincipals();
        }
        */
        principals = subject.getPrincipals();

        if (principals == null || principals.isEmpty()) {
            String msg = "Principals returned from securityManager.login( token ) returned a null or " +
                    "empty value.  This value must be non null and populated with one or more elements.";
            throw new IllegalStateException(msg);
        }
        this.principals = principals;
        authenticated = subject.isAuthenticated();
        if (token instanceof HostAuthenticationToken) {
            host = ((HostAuthenticationToken) token).getHost();
        }
        if (host != null) {
            this.host = host;
        }
        Session session = subject.getSession(false);
        if (session != null) {
            this.session = decorate(session);
        } else {
            this.session = null;
        }

    }

    @Override
    public Collection<Permission> getAllPermissions() {
        return authorizingRealm.getPermissions(this);
    }

    public void startTwoStepProcess() {
        principals.add(new TwoStepPrincipal());
    }

    public void endTwoStepProcess() {
        TwoStepPrincipal twoStepPrincipal = principals.oneByType(TwoStepPrincipal.class);
        if (twoStepPrincipal != null) {

            twoStepPrincipal.setTerminated();
            // FIXME Log when twoStepPrincipal == null
        }
    }

}
