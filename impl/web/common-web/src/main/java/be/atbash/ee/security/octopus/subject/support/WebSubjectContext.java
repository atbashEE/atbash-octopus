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
package be.atbash.ee.security.octopus.subject.support;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.mgt.WebSecurityManager;
import be.atbash.ee.security.octopus.realm.AuthorizingRealm;
import be.atbash.ee.security.octopus.session.Session;
import be.atbash.ee.security.octopus.subject.*;
import be.atbash.ee.security.octopus.subject.SecurityManager;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.MapContext;
import be.atbash.ee.security.octopus.util.OctopusCollectionUtils;
import be.atbash.ee.security.octopus.util.RequestPairSource;
import be.atbash.util.CDIUtils;
import be.atbash.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;

/**
 * Default implementation of the {@link SubjectContext} interface.  Note that the getters and setters are not
 * simple pass-through methods to an underlying attribute;  the getters will employ numerous heuristics to acquire
 * their data attribute as best as possible (for example, if {@link #getPrincipals} is invoked, if the principals aren't
 * in the backing map, it might check to see if there is a subject or session in the map and attempt to acquire the
 * principals from those objects).
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.subject.support.DefaultSubjectContext"})
public class WebSubjectContext extends MapContext implements SubjectContext, RequestPairSource {

    private static final String SECURITY_MANAGER = WebSubjectContext.class.getName() + ".SECURITY_MANAGER";

    private static final String SESSION_ID = WebSubjectContext.class.getName() + ".SESSION_ID";

    private static final String AUTHENTICATION_TOKEN = WebSubjectContext.class.getName() + ".AUTHENTICATION_TOKEN";

    private static final String AUTHENTICATION_INFO = WebSubjectContext.class.getName() + ".AUTHENTICATION_INFO";

    private static final String SUBJECT = WebSubjectContext.class.getName() + ".SUBJECT";

    private static final String PRINCIPALS = WebSubjectContext.class.getName() + ".PRINCIPALS";

    private static final String SESSION = WebSubjectContext.class.getName() + ".SESSION";

    private static final String AUTHENTICATED = WebSubjectContext.class.getName() + ".AUTHENTICATED";

    private static final String HOST = WebSubjectContext.class.getName() + ".HOST";

    public static final String SESSION_CREATION_ENABLED = WebSubjectContext.class.getName() + ".SESSION_CREATION_ENABLED";

    private static final String SERVLET_REQUEST = WebSubjectContext.class.getName() + ".SERVLET_REQUEST";
    private static final String SERVLET_RESPONSE = WebSubjectContext.class.getName() + ".SERVLET_RESPONSE";

    /**
     * The session key that is used to store subject principals.
     */
    public static final String PRINCIPALS_SESSION_KEY = WebSubjectContext.class.getName() + "_PRINCIPALS_SESSION_KEY";

    /**
     * The session key that is used to store whether or not the user is authenticated.
     */
    public static final String AUTHENTICATED_SESSION_KEY = WebSubjectContext.class.getName() + "_AUTHENTICATED_SESSION_KEY";

    private static final transient Logger log = LoggerFactory.getLogger(WebSubjectContext.class);
    private AuthorizingRealm authorizingRealm;

    public WebSubjectContext(AuthorizingRealm authorizingRealm) {
        super();
        this.authorizingRealm = authorizingRealm;
    }

    public WebSubjectContext(SubjectContext ctx) {
        super(ctx);
        this.authorizingRealm = ctx.getAuthorizingRealm();
    }

    @Override
    public SecurityManager getSecurityManager() {
        return getTypedValue(SECURITY_MANAGER, SecurityManager.class);
    }

    @Override
    public void setSecurityManager(SecurityManager securityManager) {
        nullSafePut(SECURITY_MANAGER, securityManager);
    }

    @Override
    public SecurityManager resolveSecurityManager() {
        SecurityManager securityManager = getSecurityManager();
        if (securityManager == null) {
            if (log.isDebugEnabled()) {
                log.debug("No SecurityManager available in subject context map.  " +
                        "Falling back to SecurityUtils.getSecurityManager() lookup.");
            }

            securityManager = CDIUtils.retrieveInstance(WebSecurityManager.class);
            // Set instance from CDI because we don't have one at this moment.
            setSecurityManager(securityManager);

        }
        return securityManager;
    }

    public Serializable getSessionId() {
        return getTypedValue(SESSION_ID, Serializable.class);
    }

    public void setSessionId(Serializable sessionId) {
        nullSafePut(SESSION_ID, sessionId);
    }

    public WebSubject getSubject() {
        return getTypedValue(SUBJECT, WebSubject.class);
    }

    public void setSubject(Subject subject) {
        nullSafePut(SUBJECT, subject);
    }

    public PrincipalCollection getPrincipals() {
        return getTypedValue(PRINCIPALS, PrincipalCollection.class);
    }

    public void setPrincipals(PrincipalCollection principals) {
        if (!OctopusCollectionUtils.isEmpty(principals)) {
            put(PRINCIPALS, principals);
        }
    }

    public PrincipalCollection resolvePrincipals() {
        PrincipalCollection principals = getPrincipals();

        if (OctopusCollectionUtils.isEmpty(principals)) {
            //check to see if they were just authenticated:
            AuthenticationInfo info = getAuthenticationInfo();
            if (info != null) {
                principals = info.getPrincipals();
            }
        }

        if (OctopusCollectionUtils.isEmpty(principals)) {
            WebSubject subject = getSubject();
            if (subject != null) {
                principals = subject.getPrincipals();
            }
        }

        if (OctopusCollectionUtils.isEmpty(principals)) {
            //try the session:
            Session session = resolveSession();
            if (session != null) {
                principals = (PrincipalCollection) session.getAttribute(PRINCIPALS_SESSION_KEY);
            }
        }

        setPrincipals(principals); // Keep for future usage when we try to do resolvePrincipals again.

        return principals;
    }

    public Session getSession() {
        return getTypedValue(SESSION, Session.class);
    }

    public void setSession(Session session) {
        nullSafePut(SESSION, session);
    }

    public Session resolveSession() {
        Session session = getSession();
        if (session == null) {
            //try the Subject if it exists:
            WebSubject existingSubject = getSubject();
            if (existingSubject != null) {
                session = existingSubject.getSession(false);
            }
        }

        setSession(session); // Keep for future usage when we try to do resolveSession again.
        return session;
    }

    public boolean isSessionCreationEnabled() {
        Boolean val = getTypedValue(SESSION_CREATION_ENABLED, Boolean.class);
        return val == null || val;
    }

    public void setSessionCreationEnabled(boolean enabled) {
        nullSafePut(SESSION_CREATION_ENABLED, enabled);
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
            authc = Boolean.FALSE;
        }
        /*
        FIXME ?? Needed, compare with Shiro version
        if (authc == null) {
            //see if there is an AuthenticationInfo object.  If so, the very presence of one indicates a successful
            //authentication attempt:
            AuthenticationInfo info = getAuthenticationInfo();
            authc = info != null;
        }
        */
        if (!authc) {
            //fall back to a session check:
            Session session = resolveSession();
            if (session != null) {
                Boolean sessionAuthc = (Boolean) session.getAttribute(AUTHENTICATED_SESSION_KEY);
                authc = sessionAuthc != null && sessionAuthc;
            }
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

    public String getHost() {
        return getTypedValue(HOST, String.class);
    }

    public void setHost(String host) {
        if (StringUtils.hasText(host)) {
            put(HOST, host);
        }
    }

    public String resolveHost() {
        String host = getHost();

        if (host == null) {
            //check to see if there is an AuthenticationToken from which to retrieve it:

            /*
            AuthenticationToken token = getAuthenticationToken();
            if (token instanceof HostAuthenticationToken) {
                host = ((HostAuthenticationToken) token).getHost();
            }
            */
        }

        if (host == null) {
            Session session = resolveSession();
            if (session != null) {
                host = session.getHost();
            }
        }

        if (host == null) {
            ServletRequest request = resolveServletRequest();
            if (request != null) {
                host = request.getRemoteHost();
            }
        }

        setHost(host); // Keep for future usage when we try to do resolveHost again.
        return host;
    }

    public HttpServletRequest getServletRequest() {
        return getTypedValue(SERVLET_REQUEST, HttpServletRequest.class);
    }

    public void setServletRequest(HttpServletRequest request) {
        if (request != null) {
            put(SERVLET_REQUEST, request);
        }
    }

    public HttpServletRequest resolveServletRequest() {

        HttpServletRequest request = getServletRequest();

        //fall back on existing subject instance if it exists:
        if (request == null) {
            WebSubject existing = getSubject();
            request = existing.getServletRequest();

        }
        setServletRequest(request); // Keep for future usage when we try to do resolveServletRequest again.

        return request;
    }

    @Override
    public HttpServletResponse getServletResponse() {
        return getTypedValue(SERVLET_RESPONSE, HttpServletResponse.class);
    }

    public void setServletResponse(HttpServletResponse response) {
        if (response != null) {
            put(SERVLET_RESPONSE, response);
        }
    }

    public HttpServletResponse resolveServletResponse() {

        HttpServletResponse response = getServletResponse();

        //fall back on existing subject instance if it exists:
        if (response == null) {
            WebSubject existing = getSubject();

            response = existing.getServletResponse();

        }

        setServletResponse(response); // Keep for future usage when we try to do resolveServletResponse again.

        return response;
    }

    @Override
    public AuthorizingRealm getAuthorizingRealm() {
        return authorizingRealm;
    }
}
