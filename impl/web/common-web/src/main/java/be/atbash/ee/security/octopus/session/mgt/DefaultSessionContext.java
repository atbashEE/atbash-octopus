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
package be.atbash.ee.security.octopus.session.mgt;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.session.SessionContext;
import be.atbash.ee.security.octopus.util.MapContext;
import be.atbash.ee.security.octopus.util.RequestPairSource;
import be.atbash.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.util.Map;

/**
 * Default implementation of the {@link SessionContext} interface which provides getters and setters that
 * wrap interaction with the underlying backing context map.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.session.mgt.DefaultSessionContext", "org.apache.shiro.web.session.mgt.DefaultWebSessionContext"})
public class DefaultSessionContext extends MapContext implements SessionContext, RequestPairSource {

    private static final String HOST = DefaultSessionContext.class.getName() + ".HOST";
    private static final String SESSION_ID = DefaultSessionContext.class.getName() + ".SESSION_ID";
    private static final String SERVLET_REQUEST = DefaultSessionContext.class.getName() + ".SERVLET_REQUEST";
    private static final String SERVLET_RESPONSE = DefaultSessionContext.class.getName() + ".SERVLET_RESPONSE";

    public DefaultSessionContext() {
        super();
    }

    public DefaultSessionContext(Map<String, Object> map) {
        super(map);
    }

    public String getHost() {
        return getTypedValue(HOST, String.class);
    }

    public void setHost(String host) {
        if (StringUtils.hasText(host)) {
            put(HOST, host);
        }
    }

    public Serializable getSessionId() {
        return getTypedValue(SESSION_ID, Serializable.class);
    }

    public void setSessionId(Serializable sessionId) {
        nullSafePut(SESSION_ID, sessionId);
    }

    public void setServletRequest(HttpServletRequest request) {
        if (request != null) {
            put(SERVLET_REQUEST, request);
        }
    }

    public HttpServletRequest getServletRequest() {
        return getTypedValue(SERVLET_REQUEST, HttpServletRequest.class);
    }

    public void setServletResponse(HttpServletResponse response) {
        if (response != null) {
            put(SERVLET_RESPONSE, response);
        }
    }

    public HttpServletResponse getServletResponse() {
        return getTypedValue(SERVLET_RESPONSE, HttpServletResponse.class);
    }
}
