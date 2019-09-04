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
package be.atbash.ee.security.octopus.oauth2.servlet;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import be.atbash.ee.security.octopus.oauth2.info.OAuth2InfoProvider;
import be.atbash.ee.security.octopus.session.SessionUtil;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.SavedRequest;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

/**
 *
 */
public abstract class OAuth2CallbackProcessor {

    protected Logger logger = LoggerFactory.getLogger(getClass());

    @Inject
    private OctopusJSFConfiguration jsfConfiguration;

    @Inject
    private SessionUtil sessionUtil;

    @Inject
    private OAuth2SessionAttributesUtil sessionAttributesUtil;

    /**
     * Process the callback request send by remote provider.
     * UnauthenticatedException ->
     * OAuthException ->
     *
     * @param request
     * @param response
     * @throws IOException
     */
    public abstract void processCallback(HttpServletRequest request, HttpServletResponse response) throws IOException;

    protected boolean checkCSRFToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        boolean result = true;
        String csrfToken = sessionAttributesUtil.getCSRFToken(request);
        String state = request.getParameter("state");
        if (csrfToken == null || !csrfToken.equals(state)) {
            logger.warn(String.format("The CSRF token does not match (session %s - request %s)", csrfToken, state));
            // The CSRF token do not match, deny access.
            redirectToRoot(request, response);
            result = false;
        }
        return result;

    }

    protected void redirectToRoot(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
        session.invalidate();
        // TODO is redirect to ContextPath OK?
        response.sendRedirect(request.getContextPath());
    }

    protected void doAuthenticate(HttpServletRequest request, HttpServletResponse response, OAuth2InfoProvider infoProvider) throws IOException {
        OAuth20Service service = sessionAttributesUtil.getOAuth2Service(request);
        // TODO Is it possible that no service is found on Session (direct call to URL and not as callback?)

        //Get the all important authorization code
        String code = request.getParameter(getAccessTokenParameterName());
        // TODO What if the parameter isn't available
        //Construct the access token
        OAuth2AccessToken token;
        try {
            token = service.getAccessToken(code);
        } catch (InterruptedException | ExecutionException e) {
            throw new AtbashUnexpectedException(e);
        }

        OAuth2UserToken oAuth2User = infoProvider.retrieveUserInfo(token, request);

        try {

            WebSubject subject = SecurityUtils.getSubject();
            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(subject);
            sessionUtil.invalidateCurrentSession(request);

            SecurityUtils.getSubject().login(oAuth2User);
            response.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : request.getContextPath());
        } catch (AuthenticationException e) {
            HttpSession session = request.getSession();
            session.setAttribute(OAuth2UserToken.OAUTH2_USER_INFO, oAuth2User);
            session.setAttribute("AuthenticationExceptionMessage", e.getMessage());
            // DataSecurityProvider decided that google user has no access to application
            response.sendRedirect(request.getContextPath() + jsfConfiguration.getUnauthorizedExceptionPage());
        }

    }

    protected String getAccessTokenParameterName() {
        return "code";
    }

}
