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
package be.atbash.ee.security.octopus.authc;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.util.codec.ByteSource;

import java.io.Serializable;
import java.util.Objects;

import static be.atbash.ee.security.octopus.OctopusConstants.INFO_KEY_TOKEN;

/**
 * <code>AuthenticationInfo</code> represents a Subject's (aka user's) stored account information relevant to the
 * authentication/log-in process only.
 * <p/>
 * It is important to understand the difference between this interface and the
 * {@link AuthenticationToken AuthenticationToken} interface.  <code>AuthenticationInfo</code> implementations
 * represent already-verified and stored account data, whereas an <code>AuthenticationToken</code> represents data
 * submitted for any given login attempt (which may or may not successfully match the verified and stored account
 * <code>AuthenticationInfo</code>).
 * <p/>
 * Because the act of authentication (log-in) is orthogonal to authorization (access control), this interface is
 * intended to represent only the account data needed by Octopus during an authentication attempt.  Octopus also
 * has a parallel {@link be.atbash.ee.security.octopus.authz.AuthorizationInfo AuthorizationInfo} interface for use during the
 * authorization process that references access control data such as roles and permissions.
 * <p/>
 * TODO
 * But because many if not most {@link org.apache.shiro.realm.Realm Realm}s store both sets of data for a Subject, it might be
 * convenient for a <code>Realm</code> implementation to utilize an implementation of the {@link Account Account}
 * interface instead, which is a convenience interface that combines both <code>AuthenticationInfo</code> and
 * <code>AuthorizationInfo</code>.  Whether you choose to implement these two interfaces separately or implement the one
 * <code>Account</code> interface for a given <code>Realm</code> is entirely based on your application's needs or your
 * preferences.
 * <p/>
 * <p><b>Pleae note:</b>  Since Octopus sometimes logs authentication operations, please ensure your AuthenticationInfo's
 * <code>toString()</code> implementation does <em>not</em> print out account credentials (password, etc), as these might be viewable to
 * someone reading your logs.  This is good practice anyway, and account credentials should rarely (if ever) be printed
 * out for any reason.</p>
 *
 * @see be.atbash.ee.security.octopus.authz.AuthorizationInfo AuthorizationInfo
 * @see Account
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authc.AuthenticationInfo", "org.apache.shiro.authc.SaltedAuthenticationInfo", "org.apache.shiro.authc.SimpleAuthenticationInfo"})
public class AuthenticationInfo implements Serializable {

    /**
     * The principals identifying the account associated with this AuthenticationInfo instance.
     */
    protected PrincipalCollection principals;
    /**
     * The credentials verifying the account principals.
     */
    protected Object credentials;

    protected ValidatedAuthenticationToken token;

    protected boolean oneTime = false;

    protected boolean external = false;

    /**
     * Any salt used in hashing the credentials.
     */
    protected ByteSource credentialsSalt;

    /**
     * Constructor that takes in a single 'primary' principal of the account for usage with an 'external' check like
     * LDAP
     * <p/>
     *
     * @param principal the 'primary' principal associated with the specified realm.
     */
    public AuthenticationInfo(UserPrincipal principal) {
        this(principal, (Object) null, false);
        external = true;
    }


    /**
     * Constructor that takes in a single 'primary' principal of the account and its corresponding credentials,
     * associated with the specified realm.
     * <p/>
     * This is a convenience constructor and will construct a {@link PrincipalCollection PrincipalCollection} based
     * on the {@code principal} and {@code realmName} argument.
     * authenticationInfo is possibly cached (see logic ???) // TODO
     *
     * @param principal   the 'primary' principal associated with the specified realm.
     * @param credentials the credentials that verify the given principal.
     */
    public AuthenticationInfo(UserPrincipal principal, Object credentials) {
        this(principal, credentials, false);
    }

    /**
     * Constructor that takes in a single 'primary' principal of the account and its corresponding credentials,
     * associated with the specified realm.
     * <p/>
     * This is a convenience constructor and will construct a {@link PrincipalCollection PrincipalCollection} based
     * on the {@code principal} and {@code realmName} argument.
     *
     * @param principal   the 'primary' principal associated with the specified realm.
     * @param credentials the credentials that verify the given principal.
     * @param oneTime     when oneTime set to true, the authenticationInfo will not be cached.
     */
    public AuthenticationInfo(UserPrincipal principal, Object credentials, boolean oneTime) {
        principals = new PrincipalCollection(principal);
        this.credentials = credentials;
        this.oneTime = oneTime;
    }

    /**
     * Constructor that takes in a single 'primary' principal of the account and the token used during authentication
     * (MP token, OAUth2 token, etc ...
     * <p/>
     * The token is also defined as user info with key -token.
     * The authnetication is also considered as a one time (stateless). In other scenarios use the other constructor which takes an additional boolean.
     *
     * @param principal the 'primary' principal associated with the specified realm.
     * @param token     the token that verify the given principal.
     */
    public AuthenticationInfo(UserPrincipal principal, ValidatedAuthenticationToken token) {
        this(principal, token, token != null);
    }

    /**
     * Constructor that takes in a single 'primary' principal of the account and the token used during authentication
     * (MP token, OAUth2 token, etc ...
     * <p/>
     * The token is also defined as user info with key -token
     *
     * @param principal the 'primary' principal associated with the specified realm.
     * @param token     the token that verify the given principal.
     */
    public AuthenticationInfo(UserPrincipal principal, ValidatedAuthenticationToken token, boolean oneTime) {
        principals = new PrincipalCollection(principal);
        this.token = token;
        this.oneTime = oneTime;
        principals.add(token);

        principal.addUserInfo(INFO_KEY_TOKEN, token); // 05-2019 FIXME This is no longer needed? The token is also as Principal defined.
        // But getting the principal can only by type and thus not very easy.
        // 08-2019  Used by SSOClientSecurityDataProvider
        // Verify if every token is a Principal and added to Collection?.
    }

    /**
     * Constructor that takes in a single 'primary' principal of the account, its corresponding hashed credentials,
     * the salt used to hash the credentials, and the name of the realm to associate with the principals.
     * <p/>
     * This is a convenience constructor and will construct a {@link PrincipalCollection PrincipalCollection} based
     * on the <code>principal</code> and <code>realmName</code> argument.
     *
     * @param principal         the 'primary' principal associated with the specified realm.
     * @param hashedCredentials the hashed credentials that verify the given principal.
     * @param credentialsSalt   the salt used when hashing the given hashedCredentials
     * @param realmName         the realm from where the principal and credentials were acquired.
     * @see org.apache.shiro.authc.credential.HashedCredentialsMatcher HashedCredentialsMatcher
     */
    public AuthenticationInfo(UserPrincipal principal, Object hashedCredentials, ByteSource credentialsSalt) {
        principals = new PrincipalCollection(principal);
        credentials = hashedCredentials;
        this.credentialsSalt = credentialsSalt;
    }

    /**
     * Returns all principals associated with the corresponding Subject.  Each principal is an identifying piece of
     * information useful to the application such as a username, or user id, a given name, etc - anything useful
     * to the application to identify the current <code>Subject</code>.
     * <p/>
     * The returned PrincipalCollection should <em>not</em> contain any credentials used to verify principals, such
     * as passwords, private keys, etc.  Those should be instead returned by {@link #getCredentials() getCredentials()}.
     *
     * @return all principals associated with the corresponding Subject.
     */
    public PrincipalCollection getPrincipals() {
        return principals;
    }

    /**
     * Returns the credentials associated with the corresponding Subject.  A credential verifies one or more of the
     * {@link #getPrincipals() principals} associated with the Subject, such as a password or private key.  Credentials
     * are used by particularly during the authentication process to ensure that submitted credentials
     * during a login attempt match exactly the credentials here in the <code>AuthenticationInfo</code> instance.
     *
     * @return the credentials associated with the corresponding Subject. (null when isExternalVerification() return true;
     */
    public Object getCredentials() {
        return external ? null : credentials;
    }


    /**
     * Various authentication methods (like MPToken) are only presented once and the principal id (for MPToken the jti is taken) is unique for each logon.
     * So there is no need to cache anything related to this token.
     *
     * @return when true, authentication will never be cached
     */
    public boolean isOneTimeAuthentication() {
        return oneTime;
    }

    /**
     * Determines if the 'external' verification needs to be performed, like LDAP. This mode can be triggered by
     * creating a AuthenticationInfo instance using the UserPrincipal parameter only.
     *
     * @return true
     */
    public boolean isExternalVerification() {
        return external;
    }

    /**
     * Returns the salt used to salt the account's credentials or {@code null} if no salt was used.
     *
     * @return the salt used to salt the account's credentials or {@code null} if no salt was used.
     */
    public ByteSource getCredentialsSalt() {
        return credentialsSalt;
    }

    /**
     * Returns the token from which this AuthenticationInfo is derived. This can be a different token
     * then the original token which is used in the calls.
     * <p/>
     * For example, a UserNamePasswordToken is 'exchanged' into a KeycloakUserToken which is used.
     * The KeycloakUserToken is a validated token, and thus the AuthenticationInfo doesn't needs to be passed to the CredentialMatchers anymore.
     *
     * @return
     */
    public ValidatedAuthenticationToken getValidatedToken() {
        return token;
    }

    /**
     * Returns <code>true</code> if the Object argument is an <code>instanceof AuthenticationInfo</code> and
     * its {@link #getPrincipals() principals} are equal to this instance's principals, <code>false</code> otherwise.
     *
     * @param o the object to compare for equality.
     * @return <code>true</code> if the Object argument is an <code>instanceof AuthenticationInfo</code> and
     * its {@link #getPrincipals() principals} are equal to this instance's principals, <code>false</code> otherwise.
     */
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AuthenticationInfo)) {
            return false;
        }

        AuthenticationInfo that = (AuthenticationInfo) o;

        return Objects.equals(principals, that.principals);
    }

    /**
     * Determines if the credentials supplied in this authenticationInfo are hashed. used when only hashed passwords are stored (including salt)
     *
     * @return true when salt is supplied.
     */
    public boolean isHashedPassword() {
        return credentialsSalt != null;
    }

    /**
     * Returns the hashcode of the internal {@link #getPrincipals() principals} instance.
     *
     * @return the hashcode of the internal {@link #getPrincipals() principals} instance.
     */
    public int hashCode() {
        return (principals != null ? principals.hashCode() : 0);
    }

    /**
     * Simple implementation that merely returns <code>{@link #getPrincipals() principals}.toString()</code>
     *
     * @return <code>{@link #getPrincipals() principals}.toString()</code>
     */
    public String toString() {
        return principals.toString();
    }



}
