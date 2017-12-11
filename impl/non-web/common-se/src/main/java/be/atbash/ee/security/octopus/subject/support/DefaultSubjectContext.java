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
package be.atbash.ee.security.octopus.subject.support;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.SubjectContext;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.CollectionUtils;
import be.atbash.ee.security.octopus.util.MapContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of the {@link SubjectContext} interface.  Note that the getters and setters are not
 * simple pass-through methods to an underlying attribute;  the getters will employ numerous heuristics to acquire
 * their data attribute as best as possible (for example, if {@link #getPrincipals} is invoked, if the principals aren't
 * in the backing map, it might check to see if there is a subject or session in the map and attempt to acquire the
 * principals from those objects).
 */
public class DefaultSubjectContext extends MapContext implements SubjectContext {

    // Only used in Java SE but 'hard linked' from SecurityUtil.getSubject()
    // TODO SecurityUtil hierarchy so this can be solved?

    private static final String AUTHENTICATION_TOKEN = DefaultSubjectContext.class.getName() + ".AUTHENTICATION_TOKEN";

    private static final String AUTHENTICATION_INFO = DefaultSubjectContext.class.getName() + ".AUTHENTICATION_INFO";

    private static final String SUBJECT = DefaultSubjectContext.class.getName() + ".SUBJECT";

    private static final String PRINCIPALS = DefaultSubjectContext.class.getName() + ".PRINCIPALS";

    private static final String AUTHENTICATED = DefaultSubjectContext.class.getName() + ".AUTHENTICATED";

    private static final transient Logger log = LoggerFactory.getLogger(DefaultSubjectContext.class);

    public DefaultSubjectContext() {
        super();
    }

    public DefaultSubjectContext(SubjectContext ctx) {
        super(ctx);
    }

    public Subject getSubject() {
        return getTypedValue(SUBJECT, Subject.class);
    }

    public void setSubject(Subject subject) {
        nullSafePut(SUBJECT, subject);
    }

    public PrincipalCollection getPrincipals() {
        return getTypedValue(PRINCIPALS, PrincipalCollection.class);
    }

    public void setPrincipals(PrincipalCollection principals) {
        if (!CollectionUtils.isEmpty(principals)) {
            put(PRINCIPALS, principals);
        }
    }

    public PrincipalCollection resolvePrincipals() {
        PrincipalCollection principals = getPrincipals();

        if (CollectionUtils.isEmpty(principals)) {
            //check to see if they were just authenticated:
            AuthenticationInfo info = getAuthenticationInfo();
            if (info != null) {
                principals = info.getPrincipals();
            }
        }

        if (CollectionUtils.isEmpty(principals)) {
            Subject subject = getSubject();
            if (subject != null) {
                principals = subject.getPrincipals();
            }
        }

        return principals;
    }

    public boolean isAuthenticated() {
        Boolean authc = getTypedValue(AUTHENTICATED, Boolean.class);
        return authc != null && authc;
    }

    public void setAuthenticated(boolean authc) {
        put(AUTHENTICATED, authc);
    }

    public boolean resolveAuthenticated() {
        Boolean authc = getTypedValue(AUTHENTICATED, Boolean.class);
        if (authc == null) {
            //see if there is an AuthenticationInfo object.  If so, the very presence of one indicates a successful
            //authentication attempt:
            AuthenticationInfo info = getAuthenticationInfo();
            authc = info != null;
        }

        return authc;
    }

    public AuthenticationInfo getAuthenticationInfo() {
        return getTypedValue(AUTHENTICATION_INFO, AuthenticationInfo.class);
    }

    public void setAuthenticationInfo(AuthenticationInfo info) {
        nullSafePut(AUTHENTICATION_INFO, info);
    }

    public AuthenticationToken getAuthenticationToken() {
        return getTypedValue(AUTHENTICATION_TOKEN, AuthenticationToken.class);
    }

    public void setAuthenticationToken(AuthenticationToken token) {
        nullSafePut(AUTHENTICATION_TOKEN, token);
    }

}
