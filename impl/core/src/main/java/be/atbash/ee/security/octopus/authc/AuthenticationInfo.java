/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;

import java.io.Serializable;

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
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authc.AuthenticationInfo"})
public interface AuthenticationInfo extends Serializable {

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
    PrincipalCollection getPrincipals();

    /**
     * Returns the credentials associated with the corresponding Subject.  A credential verifies one or more of the
     * {@link #getPrincipals() principals} associated with the Subject, such as a password or private key.  Credentials
     * are used by Shiro particularly during the authentication process to ensure that submitted credentials
     * during a login attempt match exactly the credentials here in the <code>AuthenticationInfo</code> instance.
     *
     * @return the credentials associated with the corresponding Subject.
     */
    Object getCredentials();

    /**
     * Various authentication methods (like MPToken) are only presented once and the principal id (for MPToken the jti is taken) is unique for each logon.
     * So there is no need to cache anything related to this token.
     *
     * @return when true, authentication will never be cached
     */
    boolean isOneTimeAuthentication();

    /**
     * Returns the token from which this AuthenticationInfo is derived. This can be a different token
     * then the original token which is used in the calls.
     * <p/>
     * For example, a UserNamePasswordToken is 'exchanged' into a KeycloakUserToken which is used.
     * The KeycloakUserToken is a validated token, and thus the AuthenticationInfo doesn't needs to be passed to the CredentialMatchers anymore.
     *
     * @return
     */
    ValidatedAuthenticationToken getValidatedToken();

}
