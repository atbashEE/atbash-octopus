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
package be.atbash.ee.security.octopus.keycloak.servlet;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.session.usage.ActiveSessionRegistry;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.keycloak.adapters.CorsHeaders;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.common.util.StreamUtil;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.jose.jws.crypto.RSAProvider;
import org.keycloak.representations.VersionRepresentation;
import org.keycloak.representations.adapters.action.AdminAction;
import org.keycloak.representations.adapters.action.LogoutAction;
import org.keycloak.representations.adapters.action.PushNotBeforeAction;
import org.keycloak.representations.adapters.action.TestAvailabilityAction;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
class OIDCActions {

    private Logger logger;

    private KeycloakDeployment deployment;

    private HttpServletRequest request;

    private HttpServletResponse response;
    private ActiveSessionRegistry activeSessionRegistry;

    public OIDCActions(KeycloakDeployment deployment, HttpServletRequest request, HttpServletResponse response, ActiveSessionRegistry activeSessionRegistry) {
        this.deployment = deployment;
        this.request = request;
        this.response = response;
        this.activeSessionRegistry = activeSessionRegistry;

        logger = LoggerFactory.getLogger(OIDCActions.class);

    }

    public boolean preflightCors() {
        // don't need to resolve deployment on cors requests.  Just need to know local cors config.
        if (!deployment.isCors()) {
            return false;
        }
        logger.debug("checkCorsPreflight " + request.getRequestURI());

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return false;
        }
        if (request.getHeader(CorsHeaders.ORIGIN) == null) {
            logger.debug("checkCorsPreflight: no origin header");
            return false;
        }
        logger.debug("Preflight request returning");
        response.setStatus(200);
        String origin = request.getHeader(CorsHeaders.ORIGIN);
        response.setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        response.setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        String requestMethods = request.getHeader(CorsHeaders.ACCESS_CONTROL_REQUEST_METHOD);
        if (requestMethods != null) {
            if (deployment.getCorsAllowedMethods() != null) {
                requestMethods = deployment.getCorsAllowedMethods();
            }
            response.setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_METHODS, requestMethods);
        }
        String allowHeaders = request.getHeader(CorsHeaders.ACCESS_CONTROL_REQUEST_HEADERS);
        if (allowHeaders != null) {
            if (deployment.getCorsAllowedHeaders() != null) {
                allowHeaders = deployment.getCorsAllowedHeaders();
            }
            response.setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_HEADERS, allowHeaders);
        }
        if (deployment.getCorsMaxAge() > -1) {
            response.setHeader(CorsHeaders.ACCESS_CONTROL_MAX_AGE, Integer.toString(deployment.getCorsMaxAge()));
        }
        return true;
    }

    public void handleLogout() {
        if (logger.isTraceEnabled()) {
            logger.trace("K_LOGOUT sent");
        }
        try {
            JWSInput token = verifyAdminRequest();
            if (token == null) {
                return;
            }
            LogoutAction action = JsonSerialization.readValue(token.getContent(), LogoutAction.class);
            if (!validateAction(action)) {
                return;
            }

            for (final String clientSession : action.getKeycloakSessionIds()) {

                activeSessionRegistry.invalidateSession(new ActiveSessionRegistry.UserSessionFinder() {
                    @Override
                    public boolean isCorrectPrincipal(UserPrincipal userPrincipal, String sessionId) {
                        return clientSession.equals(userPrincipal.getUserInfo(OctopusConstants.EXTERNAL_SESSION_ID));
                    }
                });
            }
            // FIXME Handle global logout
            // Verify but is done I guess.
            /*
            if (action.getAdapterSessionIds() != null) {
                for (String sessionId : action.getAdapterSessionIds()) {
                    activeSessionRegistry.endSession(sessionId);
                }

            } else {
                logger.debug("logout of all sessions for application '%s'", action.getResource());
                if (action.getNotBefore() > deployment.getNotBefore()) {
                    deployment.setNotBefore(action.getNotBefore());
                }
                activeSessionRegistry.endAll();
            }
            */

        } catch (Exception e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    protected void handlePushNotBefore() {
        if (logger.isTraceEnabled()) {
            logger.trace("K_PUSH_NOT_BEFORE sent");
        }
        try {
            JWSInput token = verifyAdminRequest();
            if (token == null) {
                return;
            }
            PushNotBeforeAction action = JsonSerialization.readValue(token.getContent(), PushNotBeforeAction.class);
            if (!validateAction(action)) {
                return;
            }
            deployment.setNotBefore(action.getNotBefore());
        } catch (Exception e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    protected void handleTestAvailable() {
        if (logger.isTraceEnabled()) {
            logger.trace("K_TEST_AVAILABLE sent");
        }
        try {
            JWSInput token = verifyAdminRequest();
            if (token == null) {
                return;
            }
            TestAvailabilityAction action = JsonSerialization.readValue(token.getContent(), TestAvailabilityAction.class);
            validateAction(action);
        } catch (Exception e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    protected JWSInput verifyAdminRequest() throws Exception {
        if (!request.isSecure() && deployment.getSslRequired().isRequired(request.getRemoteAddr())) {
            logger.warn("SSL is required for adapter admin action");
            response.sendError(403, "ssl required");
            return null;
        }
        String token = StreamUtil.readString(request.getInputStream());
        if (token == null) {  // TODO Verify if this situation can happen
            logger.warn("admin request failed, no token");
            response.sendError(403, "no token");
            return null;
        }

        try {
            JWSInput input = new JWSInput(token);
            if (RSAProvider.verify(input, deployment.getRealmKey())) {
                return input;
            }
        } catch (JWSInputException ignore) {
        }

        logger.warn("admin request failed, unable to verify token");
        response.sendError(403, "no token");
        return null;
    }

    protected boolean validateAction(AdminAction action) throws IOException {
        if (!action.validate()) {
            logger.warn("admin request failed, not validated" + action.getAction());
            response.sendError(400, "Not validated");
            return false;
        }
        if (action.isExpired()) {
            logger.warn("admin request failed, expired token");
            response.sendError(400, "Expired token");
            return false;
        }
        if (!deployment.getResourceName().equals(action.getResource())) {
            logger.warn("Resource name does not match");
            response.sendError(400, "Resource name does not match");
            return false;

        }
        return true;
    }

    protected void handleVersion() {
        try {
            response.setStatus(200);
            response.setHeader("Content-Type", "application/json");
            JsonSerialization.writeValueToStream(response.getOutputStream(), VersionRepresentation.SINGLETON);
        } catch (Exception e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    public String getURI() {
        return request.getRequestURI();
    }
}
