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
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.util.codec.ByteSource;

import java.util.Objects;

import static be.atbash.ee.security.octopus.OctopusConstants.INFO_KEY_TOKEN;

/**
 * Simple implementation of the {@link org.apache.shiro.authc.MergableAuthenticationInfo} interface that holds the principals and
 * credentials.
 *
 * @see org.apache.shiro.realm.AuthenticatingRealm
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authc.SimpleAuthenticationInfo"})
// FIXME Rename to ??? Or integrate with AuthenticationInfo interface. After we have sorted out 2step.
public class SimpleAuthenticationInfo implements AuthenticationInfo {

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

    /**
     * Any salt used in hashing the credentials.
     */
    protected ByteSource credentialsSalt;

    /**
     * Constructor that takes in a single 'primary' principal of the account and its corresponding credentials,
     * associated with the specified realm.
     * <p/>
     * This is a convenience constructor and will construct a {@link PrincipalCollection PrincipalCollection} based
     * on the {@code principal} and {@code realmName} argument.
     * authenticationInfo is possibly cached (see logic ???) // TODO
     * @param principal   the 'primary' principal associated with the specified realm.
     * @param credentials the credentials that verify the given principal.
     */
    public SimpleAuthenticationInfo(UserPrincipal principal, Object credentials) {
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
    public SimpleAuthenticationInfo(UserPrincipal principal, Object credentials, boolean oneTime) {
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
    public SimpleAuthenticationInfo(UserPrincipal principal, ValidatedAuthenticationToken token) {
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
    public SimpleAuthenticationInfo(UserPrincipal principal, ValidatedAuthenticationToken token, boolean oneTime) {
        principals = new PrincipalCollection(principal);
        this.token = token;
        this.oneTime = oneTime;
        principals.add(token);

        principal.addUserInfo(INFO_KEY_TOKEN, token); // FIXME This is no longer needed? The token is also as Principal defined.
        // But getting the principal can only by type and thus not very easy.
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
    public SimpleAuthenticationInfo(UserPrincipal principal, Object hashedCredentials, ByteSource credentialsSalt) {
        principals = new PrincipalCollection(principal);
        credentials = hashedCredentials;
        this.credentialsSalt = credentialsSalt;
    }

    @Override
    public PrincipalCollection getPrincipals() {
        return principals;
    }

    /**
     * Sets the identifying principal(s) represented by this instance.
     *
     * @param principals the identifying attributes of the corresponding Realm account.
     */
    // FIXME Remove, Constructor Only allowed!!
    public void setPrincipals(PrincipalCollection principals) {
        this.principals = principals;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    /**
     * Sets the credentials that verify the principals/identity of the associated Realm account.
     *
     * @param credentials attribute(s) that verify the account's identity/principals, such as a password or private key.
     */
    // FIXME Remove, Constructor Only allowed!!
    public void setCredentials(Object credentials) {
        this.credentials = credentials;
    }

    @Override
    public boolean isOneTimeAuthentication() {
        return oneTime;
    }

    /**
     * Returns the salt used to hash the credentials, or {@code null} if no salt was used or credentials were not
     * hashed at all.
     * <p/>
     * Note that this attribute is <em>NOT</em> handled in the
     * {@link #merge(AuthenticationInfo) merge} method - a hash salt is only useful within a single realm (as each
     * realm will perform it's own Credentials Matching logic), and once finished in that realm, Shiro has no further
     * use for salts.  Therefore it doesn't make sense to 'merge' salts in a multi-realm scenario.
     *
     * @return the salt used to hash the credentials, or {@code null} if no salt was used or credentials were not
     * hashed at all.
     */
    public ByteSource getCredentialsSalt() {
        return credentialsSalt;
    }

    /**
     * Sets the salt used to hash the credentials, or {@code null} if no salt was used or credentials were not
     * hashed at all.
     * <p/>
     * Note that this attribute is <em>NOT</em> handled in the
     * {@link #merge(AuthenticationInfo) merge} method - a hash salt is only useful within a single realm (as each
     * realm will perform it's own Credentials Matching logic), and once finished in that realm, Shiro has no further
     * use for salts.  Therefore it doesn't make sense to 'merge' salts in a multi-realm scenario.
     *
     * @param salt the salt used to hash the credentials, or {@code null} if no salt was used or credentials were not
     *             hashed at all.
     */
    public void setCredentialsSalt(ByteSource salt) {
        credentialsSalt = salt;
    }

    @Override
    public ValidatedAuthenticationToken getValidatedToken() {
        return token;
    }

    /**
     * Returns <code>true</code> if the Object argument is an <code>instanceof SimpleAuthenticationInfo</code> and
     * its {@link #getPrincipals() principals} are equal to this instance's principals, <code>false</code> otherwise.
     *
     * @param o the object to compare for equality.
     * @return <code>true</code> if the Object argument is an <code>instanceof SimpleAuthenticationInfo</code> and
     * its {@link #getPrincipals() principals} are equal to this instance's principals, <code>false</code> otherwise.
     */
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SimpleAuthenticationInfo)) {
            return false;
        }

        SimpleAuthenticationInfo that = (SimpleAuthenticationInfo) o;

        return Objects.equals(principals, that.principals);
    }

    @Override
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
