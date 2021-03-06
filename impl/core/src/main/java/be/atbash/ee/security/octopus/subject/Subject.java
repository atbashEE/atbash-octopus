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
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.token.AuthenticationToken;

import java.util.Collection;
import java.util.List;

/**
 * A {@code Subject} represents state and security operations for a <em>single</em> application user.
 * These operations include authentication (login/logout), authorization (access control), and
 * session access. It is Shiro's primary mechanism for single-user security functionality.
 * <h3>Acquiring a Subject</h3>
 * Note that there are many *Permission methods in this interface overloaded to accept String arguments instead of
 * {@link Permission Permission} instances. They are a convenience allowing the caller to use a String representation of
 * a {@link Permission Permission} if desired.  The underlying Authorization subsystem implementations will usually
 * simply convert these String values to {@link Permission Permission} instances and then just call the corresponding
 * type-safe method.  (Shiro's default implementations do String-to-Permission conversion for these methods using
 * {@link be.atbash.ee.security.octopus.authz.permission.PermissionResolver PermissionResolver}s.)
 * <p/>
 * These overloaded *Permission methods forgo type-saftey for the benefit of convenience and simplicity,
 * so you should choose which ones to use based on your preferences and needs.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.subject.Subject"})
public interface Subject {

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
    UserPrincipal getPrincipal();

    /**
     * Performs a login attempt for this Subject/user.  If unsuccessful,
     * an {@link AuthenticationException} is thrown, the subclass of which identifies why the attempt failed.
     * If successful, the account data associated with the submitted principals/credentials will be
     * associated with this {@code Subject} and the method will return quietly.
     * <p/>
     * Upon returning quietly, this {@code Subject} instance can be considered
     * authenticated and {@link #getPrincipal() getPrincipal()} will be non-null and
     * {@link #isAuthenticated() isAuthenticated()} will be {@code true}.
     *
     * @param token the token encapsulating the subject's principals and credentials to be passed to the
     *              Authentication subsystem for verification.
     * @throws be.atbash.ee.security.octopus.authc.AuthenticationException if the authentication attempt fails.
     */
    void login(AuthenticationToken token);

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
    PrincipalCollection getPrincipals();

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
    boolean isPermitted(String permission);

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
    boolean isPermitted(Permission permission);

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
    boolean[] isPermitted(String... permissions);

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
    boolean[] isPermitted(List<Permission> permissions);

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
    boolean isPermittedAll(String... permissions);

    /**
     * Returns {@code true} if this Subject implies all of the specified permissions, {@code false} otherwise.
     * <p/>
     * More specifically, this method determines if all of the given {@code Permission}s are
     * {@link Permission#implies(Permission) implied by} permissions already associated with this Subject.
     *
     * @param permissions the permissions to check.
     * @return true if this Subject has all of the specified permissions, false otherwise.
     */
    boolean isPermittedAll(Collection<Permission> permissions);

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
    void checkPermission(String permission) throws AuthorizationException;

    /**
     * Ensures this Subject {@link Permission#implies(Permission) implies} the specified {@code Permission}.
     * <p/>
     * If this subject's existing associated permissions do not {@link Permission#implies(Permission) imply}
     * the given permission, an {@link AuthorizationException} will be thrown.
     *
     * @param permission the Permission to check.
     * @throws AuthorizationException if this Subject does not have the permission.
     */
    void checkPermission(Permission permission) throws AuthorizationException;

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
    void checkPermissions(String... permissions) throws AuthorizationException;

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
    void checkPermissions(Collection<Permission> permissions) throws AuthorizationException;

    /**
     * Returns {@code true} if this Subject has the specified role, {@code false} otherwise.
     *
     * @param roleIdentifier the application-specific role identifier (usually a role id or role name).
     * @return {@code true} if this Subject has the specified role, {@code false} otherwise.
     */
    boolean hasRole(String roleIdentifier);

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
    boolean[] hasRoles(List<String> roleIdentifiers);

    /**
     * Returns {@code true} if this Subject has all of the specified roles, {@code false} otherwise.
     *
     * @param roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @return true if this Subject has all the roles, false otherwise.
     */
    boolean hasAllRoles(Collection<String> roleIdentifiers);

    /**
     * Asserts this Subject has the specified role by returning quietly if they do or throwing an
     * {@link AuthorizationException} if they do not.
     *
     * @param roleIdentifier the application-specific role identifier (usually a role id or role name ).
     * @throws AuthorizationException if this Subject does not have the role.
     */
    void checkRole(String roleIdentifier) throws AuthorizationException;

    /**
     * Asserts this Subject has all of the specified roles by returning quietly if they do or throwing an
     * {@link AuthorizationException} if they do not.
     *
     * @param roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @throws AuthorizationException if this Subject does not have all of the specified roles.
     */
    void checkRoles(Collection<String> roleIdentifiers) throws AuthorizationException;

    /**
     * Same as {@link #checkRoles(Collection < String > roleIdentifiers) checkRoles(Collection<String> roleIdentifiers)} but
     * doesn't require a collection as a an argument.
     * Asserts this Subject has all of the specified roles by returning quietly if they do or throwing an
     * {@link AuthorizationException} if they do not.
     *
     * @param roleIdentifiers roleIdentifiers the application-specific role identifiers to check (usually role ids or role names).
     * @throws AuthorizationException AuthorizationException
     *                                if this Subject does not have all of the specified roles.
     */
    void checkRoles(String... roleIdentifiers) throws AuthorizationException;

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
    boolean isAuthenticated();

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
    boolean isRemembered();

    /*
     * Returns the application {@code Session} associated with this Subject.  If no session exists when this
     * method is called, a new session will be created, associated with this Subject, and then returned.
     *
     * @return the application {@code Session} associated with this Subject.
     * @see #getSession(boolean)
     */
    // FIXME Usage??
    //Session getSession();

    /*
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
    // FIXME Usage??
    //Session getSession(boolean create);

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
    void logout();

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
    // FIXME Needed, Use case
    PrincipalCollection getPreviousPrincipals();

    /**
     * Returns the list of al permissions (roles are returned as instances of RolePermission)
     *
     * @return
     */
    Collection<Permission> getAllPermissions();
}
