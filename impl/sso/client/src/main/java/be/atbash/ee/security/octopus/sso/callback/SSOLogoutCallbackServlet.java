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
package be.atbash.ee.security.octopus.sso.callback;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.session.usage.ActiveSessionRegistry;
import be.atbash.ee.security.octopus.sso.config.OctopusSSOClientConfiguration;
import be.atbash.ee.security.octopus.sso.core.client.SSOFlow;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@WebServlet("/octopus/sso/SSOLogoutCallback")
public class SSOLogoutCallbackServlet extends HttpServlet {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSOLogoutCallbackServlet.class);

    @Inject
    private OctopusCoreConfiguration octopusCoreConfiguration;

    @Inject
    private OctopusSSOClientConfiguration config;

    @Inject
    private ActiveSessionRegistry activeSessionRegistry;

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        final String realToken = retrieveToken(httpServletRequest);

        activeSessionRegistry.invalidateSession((userPrincipal, sessionId) -> {
            boolean result = false;
            Object token = userPrincipal.getUserInfo(OctopusConstants.INFO_KEY_TOKEN);
            if (token instanceof OctopusSSOToken) {
                OctopusSSOToken ssoUser = (OctopusSSOToken) token;
                result = ssoUser.getAccessToken().equals(realToken);
            }
            return result;
        });
        showDebugInfo(realToken);
    }

    private String retrieveToken(HttpServletRequest req) {
        // FIXME Not all flows have the access_token
        SSOFlow ssoType = config.getSSOType();

        return req.getParameter("access_token");

    }

    private void showDebugInfo(String token) {

        if (octopusCoreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            LOGGER.info(String.format("(SSO Client) Server requested logout of User (token = %s)", token));
        }
    }
}
