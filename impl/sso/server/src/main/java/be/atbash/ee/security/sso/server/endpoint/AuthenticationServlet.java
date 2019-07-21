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
package be.atbash.ee.security.sso.server.endpoint;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.WebConstants;
import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.sso.server.config.OctopusSSOServerConfiguration;
import be.atbash.ee.security.sso.server.store.OIDCStoreData;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@WebServlet("/octopus/sso/authenticate")
public class AuthenticationServlet extends HttpServlet {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationServlet.class);

    @Inject
    private OctopusSSOServerConfiguration ssoServerConfiguration;

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private OctopusCoreConfiguration octopusCoreConfiguration;

    @Inject
    private OIDCTokenHelper oidcTokenHelper;


    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse response) throws ServletException, IOException {

        UserPrincipal userPrincipal = SecurityUtils.getSubject().getPrincipal();
         // Get the info saved bu the oidcFilter
        AuthenticationRequest request = (AuthenticationRequest) httpServletRequest.getAttribute(AbstractRequest.class.getName());

        String clientId = request.getClientID().getValue();
        IDTokenClaimsSet claimsSet = oidcTokenHelper.defineIDToken(httpServletRequest, userPrincipal, request, clientId);

        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken(ssoServerConfiguration.getOIDCTokenLength()
                , ssoServerConfiguration.getSSOAccessTokenTimeToLive(), request.getScope()));

        AuthorizationCode authorizationCode = null;
        AccessToken accessToken = null;

        SignedJWT idToken = null;

        if (request.getResponseType().impliesCodeFlow()) {
            authorizationCode = new AuthorizationCode(ssoServerConfiguration.getOIDCTokenLength());
            oidcStoreData.setAuthorizationCode(authorizationCode);

            // implicit -> idToken immediately transferred
            // code flow -> first code, then exchanged to accessToken/idToken
        } else {
            if (request.getResponseType().contains("token")) {
                // Set the variable so that the Access code is send in this response.
                accessToken = oidcStoreData.getAccessToken();
            }
            idToken = oidcTokenHelper.signIdToken(clientId, claimsSet);
        }

        oidcStoreData.setIdTokenClaimsSet(claimsSet);

        oidcStoreData.setClientId(request.getClientID());
        oidcStoreData.setScope(request.getScope());

        String userAgent = httpServletRequest.getHeader("User-Agent");
        String remoteHost = httpServletRequest.getRemoteAddr();

        String cookieToken = userPrincipal.getUserInfo(WebConstants.SSO_COOKIE_TOKEN);
        tokenStore.addLoginFromClient(SecurityUtils.getSubject().getPrincipal(), cookieToken, userAgent, remoteHost, oidcStoreData);

        State state = request.getState();

        AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(request.getRedirectionURI()
                , authorizationCode, idToken, accessToken, state, null, ResponseMode.QUERY);

        try {
            String callback = successResponse.toURI().toString();

            showDebugInfo(userPrincipal);
            response.sendRedirect(callback);

            //SecurityUtils.getSubject().logout();// Do not use logout of subject, it wil remove the cookie which we need !
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new AtbashUnexpectedException(e);

        } finally {
            httpServletRequest.getSession().invalidate();  // Don't keep the session on the SSO server
        }


    }

    private void showDebugInfo(UserPrincipal userPrincipal) {
        if (octopusCoreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            LOGGER.info(String.format("(SSO Server) User %s is authenticated and cookie written if needed.", userPrincipal.getName()));
        }
    }


}
