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
package be.atbash.ee.security.octopus.sso.callback;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authz.UnauthorizedException;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.sso.client.config.OctopusSSOServerClientConfiguration;
import be.atbash.ee.security.octopus.sso.client.requestor.CustomUserInfoValidator;
import be.atbash.ee.security.octopus.sso.client.requestor.OctopusUserRequestor;
import be.atbash.ee.security.octopus.session.SessionUtil;
import be.atbash.ee.security.octopus.sso.config.OctopusSSOClientConfiguration;
import be.atbash.ee.security.octopus.sso.core.client.SSOFlow;
import be.atbash.ee.security.octopus.sso.core.rest.DefaultPrincipalUserInfoJSONProvider;
import be.atbash.ee.security.octopus.sso.core.rest.PrincipalUserInfoJSONProvider;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOTokenConverter;
import be.atbash.ee.security.octopus.util.SavedRequest;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.util.CDIUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

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
@WebServlet("/sso/SSOCallback")
public class SSOCallbackServlet extends HttpServlet {

    @Inject
    private ExchangeForAccessCode exchangeForAccessCode;

    @Inject
    private CallbackErrorHandler callbackErrorHandler;

    @Inject
    private OctopusSSOTokenConverter octopusSSOTokenConverter;

    @Inject
    private OctopusSSOClientConfiguration ssoClientConfiguration;

    @Inject
    private OctopusCoreConfiguration coreConfiguration;

    @Inject
    private OctopusSSOServerClientConfiguration octopusSSOServerClientConfiguration;

    @Inject
    private SessionUtil sessionUtil;

    // TODO Are servlets serialized?
    private transient OctopusUserRequestor octopusUserRequestor;

    @Override
    public void init() throws ServletException {

        PrincipalUserInfoJSONProvider userInfoJSONProvider = CDIUtils.retrieveOptionalInstance(PrincipalUserInfoJSONProvider.class);
        if (userInfoJSONProvider == null) {
            userInfoJSONProvider = new DefaultPrincipalUserInfoJSONProvider();
        }

        CustomUserInfoValidator customUserInfoValidator = CDIUtils.retrieveOptionalInstance(CustomUserInfoValidator.class);

        octopusUserRequestor = new OctopusUserRequestor(coreConfiguration, octopusSSOServerClientConfiguration, octopusSSOTokenConverter, userInfoJSONProvider, customUserInfoValidator);
    }

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        SSOCallbackServletHandler handler = new SSOCallbackServletHandler(httpServletRequest, httpServletResponse, callbackErrorHandler);

        // Get the authentication response and do some basic checks about it.
        AuthenticationSuccessResponse successResponse = handler.getAuthenticationResponse();

        if (successResponse == null) {
            // The call contained an Error Object or some validations failed.
            // The callbackErrorHandler is already called with the problem and null indicates that there is no successResponse.
            return;
        }

        BearerAccessToken accessToken = null;

        if (ssoClientConfiguration.getSSOType() == SSOFlow.AUTHORIZATION_CODE) {
            //get AccessToken from AuthorizationCode
            accessToken = handler.getAccessTokenFromAuthorizationCode(successResponse, exchangeForAccessCode);
        }

        if (ssoClientConfiguration.getSSOType() == SSOFlow.IMPLICIT) {
            // We received an (Bearer)AccessToken because of the implicit flow.
            // Accesstoken is here always Bearer Access token!! Typecast is safe
            accessToken = (BearerAccessToken) successResponse.getAccessToken();

            if (accessToken == null) {
                ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-014", "Missing Access code");
                callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);
            }
        }

        if (accessToken == null) {
            // There was some issue retrieving the accessToken.
            return;
        }

        // Retrieve user info from the accessToken
        // FIXME What if idToken was defined at scope.
        OctopusSSOToken user = handler.retrieveUser(octopusUserRequestor, accessToken);

        if (user == null) {
            // There was an issue retrieving the user.
            return;
        }
        try {

            sessionUtil.invalidateCurrentSession(httpServletRequest);

            // Do the login
            SecurityUtils.getSubject().login(user);

            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(httpServletRequest);
            try {
                httpServletResponse.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : httpServletRequest.getContextPath());
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new AtbashUnexpectedException(e);
            }

        } catch (UnauthorizedException e) {
            handleException(httpServletRequest, httpServletResponse, e, user);
        }

    }

    private void handleException(HttpServletRequest request, HttpServletResponse resp, Throwable e, OctopusSSOToken user) {
        HttpSession sess = request.getSession();
        sess.invalidate();

        // With a new HttpSession.
        sess = request.getSession(true);
        sess.setAttribute(OctopusSSOToken.class.getSimpleName(), user);
        sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
        // The SSOAfterSuccessfulLoginHandler found that the user doesn't have the required access permission
        try {
            resp.sendRedirect(request.getContextPath() + ssoClientConfiguration.getUnauthorizedExceptionPage());
        } catch (IOException ioException) {
            // OWASP A6 : Sensitive Data Exposure
            throw new AtbashUnexpectedException(ioException);

        }
    }

}
