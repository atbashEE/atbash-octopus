/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.filter;

import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.config.SessionHijackingLevel;
import be.atbash.ee.security.octopus.session.usage.ActiveSessionRegistry;
import be.atbash.ee.security.octopus.session.usage.SessionInfo;
import be.atbash.ee.security.octopus.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 *
 */
@ApplicationScoped
public class SessionHijackingFilter extends AdviceFilter {

    public static final String OCTOPUS_SESSION_HIJACKING_ATTEMPT = "OctopusSessionHijackingAttempt";

    private Logger logger = LoggerFactory.getLogger(SessionHijackingFilter.class);

    @Inject
    private ActiveSessionRegistry activeSessionRegistry;

    @Inject
    private OctopusCoreConfiguration octopusCoreConfiguration;

    @Inject
    private OctopusJSFConfiguration jsfConfiguration;

    @PostConstruct
    public void init() {
        setName("sh");
    }

    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        boolean result = true;
        if (jsfConfiguration.getSessionHijackingLevel() != SessionHijackingLevel.OFF) {
            HttpServletRequest httpServletRequest = WebUtils.toHttp(request);

            if (!WebUtils._isSessionCreationEnabled(httpServletRequest)) {
                // probably we are using REST Endpoints also available within the app and since we don't have any session, we can't Hijack it :)
                return true;
            }

            SessionInfo info = activeSessionRegistry.getInfo(httpServletRequest);

            // We don't have any session (info) yet, so can't determine if there is a Hijack.
            if (info == null) {
                return true;
            }
            String userAgent = httpServletRequest.getHeader("User-Agent");
            result = info.getUserAgent().equals(userAgent);

            if (result && jsfConfiguration.getSessionHijackingLevel() == SessionHijackingLevel.ON) {

                String remoteHost = request.getRemoteAddr();
                result = info.getRemoteHost().equals(remoteHost);
            }

            if (!result) {
                // Session Hijacking detected, so stop this request and inform other session.
                HttpServletResponse servletResponse = WebUtils.toHttp(response);
                servletResponse.setStatus(401);
                servletResponse.getWriter().write("Refused by the Session Hijacking Protection");

                info.getHttpSession().setAttribute(OCTOPUS_SESSION_HIJACKING_ATTEMPT, Boolean.TRUE);


                if (octopusCoreConfiguration.showDebugFor().contains(Debug.SESSION_HIJACKING)) {
                    String remoteHost = request.getRemoteAddr();
                    logger.info(String.format("Refused by the Session Hijacking Protection \nUser agent %s - %s\nRemote host %s  - %s", info.getUserAgent(), userAgent, info.getRemoteHost(), remoteHost));
                }

            }
        }

        return result;

    }
}
