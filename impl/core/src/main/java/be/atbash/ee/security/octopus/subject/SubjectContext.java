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
package be.atbash.ee.security.octopus.subject;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.realm.AuthorizingRealm;
import be.atbash.ee.security.octopus.token.AuthenticationToken;

import java.util.Map;

/**
 * A {@code SubjectContext} is a 'bucket' of data presented to a {@link SecurityManager} or {@link DefaultSubjectFactory} which interprets
 * this data to construct {@link org.apache.shiro.subject.Subject Subject} instances.  It is essentially a Map of data
 * with a few additional type-safe methods for easy retrieval of objects commonly used to construct Subject instances.
 * <p/>
 * While this interface contains type-safe setters and getters for common data types, the map can contain anything
 * additional that might be needed by the {@link SecurityManager} or
 * {@link org.apache.shiro.mgt.SubjectFactory SubjectFactory} implementation to construct {@code Subject} instances.
 * <h2>Data Resolution</h2>
 * The {@link SubjectContext} interface also allows for heuristic resolution of data used to construct a subject
 * instance.  That is, if an attribute has not been explicitly provided via a setter method, the {@code resolve*}
 * methods can use heuristics to obtain that data in another way from other attributes.
 * <p/>
 * For example, if one calls {@link #getPrincipals()} and no principals are returned, perhaps the principals exist
 * in the {@link #getSession() session} or another attribute in the context.  The {@link #resolvePrincipals()} will know
 * how to resolve the principals based on heuristics.  If the {@code resolve*} methods return {@code null} then the
 * data could not be achieved by any heuristics and must be considered as not available in the context.
 * <p/>
 * The general idea is that the normal getters can be called to see if the value was explicitly set.  The
 * {@code resolve*} methods should be used when actually constructing the {@code Subject} instance to ensure the most
 * specific/accurate data can be used.
 * <p/>
 * <b>USAGE</b>: Most Shiro end-users will never use a {@code SubjectContext} instance directly and instead will use a
 * {@link Subject.Builder} (which internally uses a {@code SubjectContext}) and build {@code Subject} instances that
 * way.
 *
 * @see org.apache.shiro.mgt.SecurityManager#createSubject SecurityManager.createSubject
 * @see org.apache.shiro.mgt.SubjectFactory SubjectFactory
 */
public interface SubjectContext extends Map<String, Object> {

    /**
     * Returns any existing {@code Subject} that may be in use at the time the new {@code Subject} instance is
     * being created.
     * <p/>
     * This is typically used in the case where the existing {@code Subject} instance returned by
     * this method is unauthenticated and a new {@code Subject} instance is being created to reflect a successful
     * authentication - you want to return most of the state of the previous {@code Subject} instance when creating the
     * newly authenticated instance.
     *
     * @return any existing {@code Subject} that may be in use at the time the new {@code Subject} instance is
     * being created.
     */
    Subject getSubject();

    /**
     * Sets the existing {@code Subject} that may be in use at the time the new {@code Subject} instance is
     * being created.
     * <p/>
     * This is typically used in the case where the existing {@code Subject} instance returned by
     * this method is unauthenticated and a new {@code Subject} instance is being created to reflect a successful
     * authentication - you want to return most of the state of the previous {@code Subject} instance when creating the
     * newly authenticated instance.
     *
     * @param subject the existing {@code Subject} that may be in use at the time the new {@code Subject} instance is
     *                being created.
     */
    void setSubject(Subject subject);

    /**
     * Returns the principals (aka identity) that the constructed {@code Subject} should reflect.
     *
     * @return the principals (aka identity) that the constructed {@code Subject} should reflect.
     */
    PrincipalCollection getPrincipals();

    PrincipalCollection resolvePrincipals();

    /**
     * Sets the principals (aka identity) that the constructed {@code Subject} should reflect.
     *
     * @param principals the principals (aka identity) that the constructed {@code Subject} should reflect.
     */
    void setPrincipals(PrincipalCollection principals);

    /**
     * Returns {@code true} if the constructed {@code Subject} should be considered authenticated, {@code false}
     * otherwise.  Be careful setting this value to {@code true} - you should know what you are doing and have a good
     * reason for ignoring Shiro's default authentication state mechanisms.
     *
     * @return {@code true} if the constructed {@code Subject} should be considered authenticated, {@code false}
     * otherwise.
     */
    boolean isAuthenticated();

    /**
     * Sets whether or not the constructed {@code Subject} instance should be considered as authenticated.  Be careful
     * when specifying {@code true} - you should know what you are doing and have a good reason for ignoring Shiro's
     * default authentication state mechanisms.
     *
     * @param authc whether or not the constructed {@code Subject} instance should be considered as authenticated.
     */
    void setAuthenticated(boolean authc);

    boolean resolveAuthenticated();

    AuthenticationInfo getAuthenticationInfo();

    void setAuthenticationInfo(AuthenticationInfo info);

    AuthenticationToken getAuthenticationToken();

    void setAuthenticationToken(AuthenticationToken token);

    AuthorizingRealm getAuthorizingRealm();
}
