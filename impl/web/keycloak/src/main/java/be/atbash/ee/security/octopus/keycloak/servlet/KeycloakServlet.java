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
package be.atbash.ee.security.octopus.keycloak.servlet;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.keycloak.adapter.AccessTokenHandler;
import be.atbash.ee.security.octopus.keycloak.adapter.KeycloakDeploymentHelper;
import be.atbash.ee.security.octopus.keycloak.adapter.KeycloakUserToken;
import be.atbash.ee.security.octopus.keycloak.adapter.OIDCAuthenticationException;
import be.atbash.ee.security.octopus.keycloak.config.OctopusKeycloakConfiguration;
import be.atbash.ee.security.octopus.util.SavedRequest;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.AdapterUtils;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OIDCAuthenticationError;
import org.keycloak.adapters.ServerRequest;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.enums.TokenStore;
import org.keycloak.representations.AccessTokenResponse;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 *
 */
@WebServlet("/keycloak/*")
public class KeycloakServlet extends HttpServlet {

    @Inject
    private Logger logger;

    @Inject
    private OctopusJSFConfiguration jsfConfiguration;

    @Inject
    private OctopusKeycloakConfiguration keycloakConfiguration;

    private KeycloakDeployment deployment;

    @Override
    public void init() throws ServletException {
        deployment = KeycloakDeploymentHelper.loadDeploymentDescriptor(keycloakConfiguration.getLocationKeycloakFile());
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        String code = getCode(request);
        if (code == null) {

            String state = AdapterUtils.generateId();
            request.getSession().setAttribute(OAuth2Constants.STATE, state);

            String redirectUri = getRedirectUri(request, state);
            try {
                WebUtils.issueRedirect(request, response, redirectUri, null, false, false);
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new AtbashUnexpectedException(e);

            }
        } else {
            try {
                authenticate(request, response, code);
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new AtbashUnexpectedException(e);

            }
        }

    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        OIDCActions oidcActions = new OIDCActions(deployment, request, response);
        handleRequest(oidcActions);
        // TODO Handle the return case false meaning action did not result in some code execution.
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        OIDCActions oidcActions = new OIDCActions(deployment, request, response);
        handleRequest(oidcActions);
        // TODO Handle the return case false meaning action did not result in some code execution.
    }

    private boolean handleRequest(OIDCActions oidcActions) {
        String requestUri = oidcActions.getURI();
        logger.debug("adminRequest {0}", requestUri);
        if (oidcActions.preflightCors()) {
            return true;
        }
        if (requestUri.endsWith(AdapterConstants.K_LOGOUT)) {
            oidcActions.handleLogout();
            return true;
        } else if (requestUri.endsWith(AdapterConstants.K_PUSH_NOT_BEFORE)) {
            oidcActions.handlePushNotBefore();
            return true;
        } else if (requestUri.endsWith(AdapterConstants.K_VERSION)) {
            oidcActions.handleVersion();
            return true;
        } else if (requestUri.endsWith(AdapterConstants.K_TEST_AVAILABLE)) {
            oidcActions.handleTestAvailable();
            return true;
        }
        return false;
    }

    private String getCode(HttpServletRequest request) {
        return getQueryParamValue(request, OAuth2Constants.CODE);
    }

    private String getState(HttpServletRequest request) {
        return getQueryParamValue(request, OAuth2Constants.STATE);
    }

    private String getQueryParamValue(HttpServletRequest request, String paramName) {
        return request.getParameter(paramName);
    }

    private String getRedirectUri(HttpServletRequest request, String state) {
        String url = WebUtils.determineRoot(request) + "/keycloak";
        // log.debugf("callback uri: %s", url);
        /*
        if (!facade.getRequest().isSecure() && deployment.getSslRequired().isRequired(facade.getRequest().getRemoteAddr())) {
            int port = sslRedirectPort();
            if (port < 0) {
                // disabled?
                return null;
            }
            KeycloakUriBuilder secureUrl = KeycloakUriBuilder.fromUri(url).scheme("https").port(-1);
            if (port != 443) {
                secureUrl.port(port);
            }
            url = secureUrl.build().toString();
        }
        */

        /*
        String idpHint = getQueryParamValue(AdapterConstants.KC_IDP_HINT);
        url = UriUtils.stripQueryParam(url, AdapterConstants.KC_IDP_HINT);

        String scope = getQueryParamValue(OAuth2Constants.SCOPE);
        url = UriUtils.stripQueryParam(url, OAuth2Constants.SCOPE);

        String prompt = getQueryParamValue(OAuth2Constants.PROMPT);
        url = UriUtils.stripQueryParam(url, OAuth2Constants.PROMPT);

        String maxAge = getQueryParamValue(OAuth2Constants.MAX_AGE);
        url = UriUtils.stripQueryParam(url, OAuth2Constants.MAX_AGE);
*/
        KeycloakUriBuilder redirectUriBuilder = deployment.getAuthUrl().clone()
                .queryParam(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.CODE)
                .queryParam(OAuth2Constants.CLIENT_ID, deployment.getResourceName())
                .queryParam(OAuth2Constants.REDIRECT_URI, url)
                .queryParam(OAuth2Constants.STATE, state)
                .queryParam("login", "true");

        /*
        TODO Support this; prefill the username field of login form
        if (loginHint != null && loginHint.length() > 0) {
            redirectUriBuilder.queryParam("login_hint", loginHint);
        }
        */

        String idpHint = keycloakConfiguration.getIdpHint();
        if (idpHint != null && idpHint.length() > 0) {
            redirectUriBuilder.queryParam(AdapterConstants.KC_IDP_HINT, idpHint);
        }


        /*
        if (prompt != null && prompt.length() > 0) {
            redirectUriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
        }
        if (maxAge != null && maxAge.length() > 0) {
            redirectUriBuilder.queryParam(OAuth2Constants.MAX_AGE, maxAge);
        }
        */

        String scope = keycloakConfiguration.getScopes();
        scope = attachOIDCScope(scope);
        redirectUriBuilder.queryParam(OAuth2Constants.SCOPE, scope);

        return redirectUriBuilder.build().toString();
    }

    public void authenticate(HttpServletRequest request, HttpServletResponse response, String code) throws IOException {
        // abort if not HTTPS
        /*
        if (!isRequestSecure() && deployment.getSslRequired().isRequired(facade.getRequest().getRemoteAddr())) {
            log.error("Adapter requires SSL. Request: " + facade.getRequest().getURI());
            return challenge(403, OIDCAuthenticationError.Reason.SSL_REQUIRED, null);
        }
        */

        checkCsrfToken(request, response);

        AccessTokenResponse tokenResponse = retrieveToken(request, response, code);
        if (tokenResponse == null) {
            // If call failed to, error already send so sto processing
            return;
        }

        KeycloakUserToken user;
        try {
            user = AccessTokenHandler.extractUser(deployment, tokenResponse);
        } catch (OIDCAuthenticationException ex) {
            sendError(response, ex.getReason());
            return;

        }

        try {

            // FIXME Is this required here or done already as part of the login?
            //sessionUtil.invalidateCurrentSession(request);

            SecurityUtils.getSubject().login(user);

            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);
            response.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : request.getContextPath());
        } catch (AuthenticationException e) {
            HttpSession sess = request.getSession();
            //sess.setAttribute(OAuth2User.OAUTH2_USER_INFO, oAuth2User); TODO
            sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
            // DataSecurityProvider decided that  user has no access to application
            // TODO use Webutils.issueRedirect
            response.sendRedirect(request.getContextPath() + jsfConfiguration.getUnauthorizedExceptionPage());
        }

        logger.debug("successful authenticated");

    }

    private String attachOIDCScope(String scopeParam) {
        return scopeParam != null && !scopeParam.isEmpty() ? "openid " + scopeParam : "openid";
    }

    private AccessTokenResponse retrieveToken(HttpServletRequest request, HttpServletResponse response, String code) throws IOException {
        AccessTokenResponse result = null;
        String strippedOauthParametersRequestUri = stripOauthParametersFromRedirect(request);
        try {
            // For COOKIE store we don't have httpSessionId and single sign-out won't be available
            String httpSessionId = deployment.getTokenStore() == TokenStore.SESSION ? request.getSession().getId() : null;
            result = ServerRequest.invokeAccessCodeToToken(deployment, code, strippedOauthParametersRequestUri, httpSessionId);
        } catch (ServerRequest.HttpFailure failure) {
            logger.error("failed to turn code into token");
            logger.error("status from server: " + failure.getStatus());
            if (failure.getStatus() == 400 && failure.getError() != null) {
                logger.error("   " + failure.getError());
            }
            sendError(response, OIDCAuthenticationError.Reason.CODE_TO_TOKEN_FAILURE);

        } catch (IOException e) {
            logger.error("failed to turn code into token", e);
            sendError(response, OIDCAuthenticationError.Reason.CODE_TO_TOKEN_FAILURE);
        }
        return result;

    }

    private void checkCsrfToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        logger.debug("checking state cookie for after code");
        if (!checkStateCookie(request)) {
            logger.warn("The CSRF token does not match");
            // The CSRF token do not match, deny access.
            HttpSession sess = request.getSession();
            sess.invalidate();
            response.sendRedirect(request.getContextPath());
        }
    }

    private void sendError(HttpServletResponse response, OIDCAuthenticationError.Reason errorCode) throws IOException {
        response.sendError(HttpServletResponse.SC_FORBIDDEN, errorCode.name());
    }

    /**
     * strip out unwanted query parameters and redirect so bookmarks don't retain oauth protocol bits
     */
    protected String stripOauthParametersFromRedirect(HttpServletRequest request) {
        String url = request.getRequestURL().toString();
        KeycloakUriBuilder builder = KeycloakUriBuilder.fromUri(url)
                .replaceQueryParam(OAuth2Constants.CODE, null)
                .replaceQueryParam(OAuth2Constants.STATE, null);
        return builder.build().toString();
    }

    public boolean checkStateCookie(HttpServletRequest request) {
        return request.getSession().getAttribute(OAuth2Constants.STATE).equals(getState(request));
    }

}
