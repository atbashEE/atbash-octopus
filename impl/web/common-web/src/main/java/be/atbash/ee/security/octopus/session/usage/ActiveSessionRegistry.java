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
package be.atbash.ee.security.octopus.session.usage;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authc.event.LogonEvent;
import be.atbash.ee.security.octopus.authc.event.LogoutEvent;
import be.atbash.ee.security.octopus.authc.event.RememberMeLogonEvent;
import be.atbash.ee.security.octopus.config.OctopusWebConfiguration;
import be.atbash.ee.security.octopus.session.event.SessionTimeoutEvent;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.WebUtils;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Event;
import javax.enterprise.event.Observes;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.*;

/**
 *
 */
@ApplicationScoped
public class ActiveSessionRegistry {

    @Inject
    private Logger logger;

    @Inject
    private OctopusWebConfiguration webConfiguration;

    private Map<String, SessionInfo> sessionRegistry = new HashMap<>();
    // sessionId

    @Inject
    private Event<SessionTimeoutEvent> sessionTimeoutEvent;

    public void onApplicationUsageEvent(@Observes SessionRegistryEvent event) {

        traceUsage(event);

        switch (event.getUserAction()) {

            case FIRST_ACCESS:
                sessionRegistry.put(event.getSessionId(), newApplicationUsageInfo(event.getSession()));
                break;
            case LOGON:
                if (webConfiguration.isSingleSession()) {
                    logoutOtherSessions(event.getUserPrincipal(), event.getSessionId());
                }

                SessionInfo sessionInfo = sessionRegistry.get(event.getSessionId());
                sessionInfo.setAuthenticationToken(event.getAuthenticationToken());
                sessionInfo.setUserPrincipal(event.getUserPrincipal());

                break;
            case REMEMBER_ME_LOGON:
                HttpSession session = event.getHttpServletRequest().getSession();

                String remoteHost = event.getHttpServletRequest().getRemoteAddr();
                String userAgent = event.getHttpServletRequest().getHeader("User-Agent");

                // OK, not ideal but we overwrite now the existing information we have.
                // Mainly because the session was created at a time where we don't have access to the ServletRequest (without using some ThreadLocal hacks)

                sessionRegistry.put(event.getSessionId(), new SessionInfo(session, remoteHost, userAgent));

                break;
            case LOGOUT:
                sessionRegistry.get(event.getSessionId()).clearAuthenticationInfo();
                break;
            case SESSION_END:
                SessionInfo usageInfo = sessionRegistry.get(event.getSessionId());
                if (usageInfo.isAuthenticated()) {
                    // When the user explicitly logs out himself, the LOGOUT step is done first and we have here thus anonymous user
                    // So this means there was a HTTPSession timeout
                    sessionTimeoutEvent.fire(new SessionTimeoutEvent(usageInfo.getUserPrincipal()));
                }
                sessionRegistry.remove(event.getSessionId());
                break;
            default:
                throw new IllegalArgumentException("UserAction " + event.getUserAction() + " not supported");
        }
    }

    private void traceUsage(@Observes SessionRegistryEvent event) {
        String userName = "(anonymous))";
        UserPrincipal userPrincipal = event.getUserPrincipal();
        if (userPrincipal != null) {
            userName = userPrincipal.getUserName();
        }
        logger.trace(String.format("(%s) New action %s for Session Registry on application %s for user %s", event.getSessionId(), event.getUserAction(), getContextRoot(event.getHttpServletRequest()), userName));
    }

    private String getContextRoot(HttpServletRequest httpServletRequest) {

        HttpServletRequest request = httpServletRequest == null ? getServletRequest() : httpServletRequest;
        if (request != null) {
            return request.getContextPath();
        } else {
            return "(unknown)";
        }
    }

    private void logoutOtherSessions(final UserPrincipal userPrincipalFromNewLogin, final String sessionIdNewLogin) {

        invalidateSession(new UserSessionFinder() {
            @Override
            public boolean isCorrectPrincipal(UserPrincipal userPrincipal, String sessionId) {
                return !sessionIdNewLogin.equals(sessionId) && userPrincipal.equals(userPrincipalFromNewLogin);
            }
        });
    }

    private SessionInfo newApplicationUsageInfo(HttpSession session) {
        String remoteHost;
        String userAgent;
        //if (ThreadContext.getSecurityManager() != null) {
        // If the Cookie Manager authenticate a user The SubjectDAO want to store it in the Session
        // And no Subject/Security manager is available at that time.
        // TODO Verify the next 2 comments; There is the OctopusSecurityManager.save() adjustment.
        // What if we use cookie for regular apps (non SSO)?
        // Need the info for the upcoming Session Hijack protection.
        HttpServletRequest httpRequest = getServletRequest();
        if (httpRequest == null) {
            return null;
        }
        remoteHost = httpRequest.getRemoteAddr();
        userAgent = httpRequest.getHeader("User-Agent");
        //}
        return new SessionInfo(session, remoteHost, userAgent);

    }

    private HttpServletRequest getServletRequest() {

        WebSubject webSubject = SecurityUtils.getSubject();
        // It is possible that we need this info before a Subject is available (Cookie remembered scenario where cookie is found)
        return webSubject == null ? null : webSubject.getServletRequest();
    }

    public void onLogin(@Observes LogonEvent logonEvent) {
        HttpServletRequest httpRequest = getServletRequest();
        // There are also use cases where we have a login() from a REST call with noSessionCreation :)
        if (WebUtils._isSessionCreationEnabled(httpRequest)) {
            onApplicationUsageEvent(new SessionRegistryEvent(httpRequest.getSession().getId(), logonEvent.getUserPrincipal(), logonEvent.getAuthenticationToken()));
        }
    }

    public void onLoginFromRememberMe(@Observes RememberMeLogonEvent event) {
        WebSubject webSubject = (WebSubject) event.getSubject();
        HttpServletRequest httpRequest = webSubject.getServletRequest();
        // There are also use cases where we have a login() from a REST call with noSessionCreation :)
        if (WebUtils._isSessionCreationEnabled(httpRequest)) {
            onApplicationUsageEvent(new SessionRegistryEvent(httpRequest, webSubject.getPrincipal()));
        }
    }

    public void onLogout(@Observes LogoutEvent logoutEvent) {
        HttpServletRequest httpRequest = getServletRequest();
        // There are also use cases where we have a login() from a REST call with noSessionCreation :)
        if (WebUtils._isSessionCreationEnabled(httpRequest)) {
            onApplicationUsageEvent(new SessionRegistryEvent(httpRequest.getSession().getId()));
        }
    }

    public void invalidateSession(UserSessionFinder userSessionFinder) {

        // We can't use for loop nor iterator !!
        // The HttpSession.invalidate() will trigger the event and removal of entries within sessionRegistry
        // And thus resulting in concurrent modification exceptions.
        List<HttpSession> toBeInvalidated = new ArrayList<>();
        for (Map.Entry<String, SessionInfo> entry : sessionRegistry.entrySet()) {
            if (entry.getValue().isAuthenticated()) {
                if (userSessionFinder.isCorrectPrincipal(entry.getValue().getUserPrincipal(), entry.getValue().getSessionId())) {
                    toBeInvalidated.add(entry.getValue().getHttpSession());
                }
            }
        }

        // and now it is safe to invalidate the sessions :)
        for (HttpSession httpSession : toBeInvalidated) {
            try {
                httpSession.invalidate();
            } catch (IllegalStateException e) {
                // FIXME finding out why this can happen (missing a cleanup somewhere)
                logger.warn(e.getMessage());
            }
        }
    }

    public SessionInfo getInfo(HttpServletRequest httpRequest) {
        SessionInfo result = null;
        if (WebUtils._isSessionCreationEnabled(httpRequest)) {
            String sessionId = httpRequest.getSession().getId();
            result = sessionRegistry.get(sessionId);
        }
        return result;
    }

    public Collection<SessionInfo> getAllSessionInfo() {
        return sessionRegistry.values();
    }

    // Since we don't use Java 8, yet :)
    public interface UserSessionFinder {
        boolean isCorrectPrincipal(UserPrincipal userPrincipal, String sessionId);
    }
}
