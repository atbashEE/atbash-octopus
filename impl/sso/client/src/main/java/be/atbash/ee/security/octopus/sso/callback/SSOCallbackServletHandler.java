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

import be.atbash.ee.security.octopus.server.requestor.OctopusUserRequestor;
import be.atbash.ee.security.octopus.sso.core.OctopusRetrievalException;
import be.atbash.ee.security.octopus.sso.core.client.OpenIdVariableClientData;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

/**
 *
 */

class SSOCallbackServletHandler {


    private HttpServletRequest httpServletRequest;
    private HttpServletResponse httpServletResponse;
    private CallbackErrorHandler callbackErrorHandler;

    private OpenIdVariableClientData variableClientData;

    SSOCallbackServletHandler(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, CallbackErrorHandler callbackErrorHandler) {
        this.httpServletRequest = httpServletRequest;
        this.httpServletResponse = httpServletResponse;
        this.callbackErrorHandler = callbackErrorHandler;
    }

    AuthenticationSuccessResponse getAuthenticationResponse() {
        // FIXME variableClientData should be set through constructor.
        HttpSession session = httpServletRequest.getSession(true);

        variableClientData = (OpenIdVariableClientData) session.getAttribute(OpenIdVariableClientData.class.getName());

        return verifyRequestStructural(httpServletRequest, httpServletResponse, variableClientData);

    }

    private AuthenticationSuccessResponse verifyRequestStructural(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, OpenIdVariableClientData variableClientData) {
        ErrorObject errorObject = null;

        // FIXME Move this test outside this class before variableClientData set through constructor.
        if (variableClientData == null) {
            errorObject = new ErrorObject("OCT-SSO-CLIENT-012", "Request did not originate from this session");
            callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);
            return null;

        }
        String query = httpServletRequest.getQueryString();
        AuthenticationResponse authenticationResponse = null;
        State receivedState;
        try {
            URI responseURL = new URI("?" + query);

            authenticationResponse = AuthenticationResponseParser.parse(responseURL);
        } catch (URISyntaxException e) {
            errorObject = new ErrorObject("OCT-SSO-CLIENT-001", e.getMessage());
        } catch (ParseException e) {
            // TODO Can only happen with response= in query (When is this generated as it related a JWT reply)
            errorObject = new ErrorObject("OCT-SSO-CLIENT-002", e.getMessage());
        }

        if (authenticationResponse instanceof AuthenticationErrorResponse) {
            AuthenticationErrorResponse errorResponse = (AuthenticationErrorResponse) authenticationResponse;
            errorObject = errorResponse.getErrorObject();
            if (errorObject.getCode() == null || errorObject.getDescription() == null) {
                errorObject = errorObject.setDescription(errorObject.getDescription() + " -- AuthenticationErrorResponse for url" + query);
            }
            receivedState = errorResponse.getState();
        } else {
            if (authenticationResponse == null) {
                // Happens when AuthenticationResponseParser.parse(responseURL); throws Exception
                receivedState = findStateFromParameters(query);
            } else {
                receivedState = authenticationResponse.getState();
            }
        }

        if (errorObject == null) {
            errorObject = checkState(variableClientData, receivedState);
        }

        if (errorObject != null) {
            callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);
            return null;
        }
        return authenticationResponse.toSuccessResponse();
    }

    private State findStateFromParameters(String query) {
        State result = null;
        Map<String, List<String>> params = URLUtils.parseParameters(query);
        if (params.containsKey("state")) {
            result = State.parse(params.get("state").get(0)); // FIXME Only the first?
        }
        return result;
    }

    private ErrorObject checkState(OpenIdVariableClientData variableClientData, State state) {
        ErrorObject result = null;

        if (!variableClientData.getState().equals(state)) {
            result = new ErrorObject("OCT-SSO-CLIENT-011", "Request has an invalid 'state' value");
        }
        return result;

    }

    BearerAccessToken getAccessTokenFromAuthorizationCode(AuthenticationSuccessResponse successResponse, ExchangeForAccessCode exchangeForAccessCode) {
        AuthorizationCode authorizationCode = successResponse.getAuthorizationCode();
        // Check if we received an Authorization code.
        if (authorizationCode == null) {
            ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-013", "Missing Authorization code");
            callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);
            return null;
        }

        return exchangeForAccessCode.doExchange(httpServletResponse, variableClientData, authorizationCode);
    }

    OctopusSSOToken retrieveUser(OctopusUserRequestor octopusUserRequestor, BearerAccessToken accessToken) {
        OctopusSSOToken result = null;
        try {
            result = octopusUserRequestor.getOctopusSSOUser(variableClientData, accessToken);
        } catch (OctopusRetrievalException e) {
            callbackErrorHandler.showErrorMessage(httpServletResponse, e.getErrorObject());

        } catch (java.text.ParseException e) {
            ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-018", "User Info endpoint response JWT validation failure : " + e.getMessage());
            callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);
        } catch (ParseException e) {
            ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-017", "User Info endpoint response validation failure : " + e.getMessage());
            callbackErrorHandler.showErrorMessage(httpServletResponse, errorObject);

        } catch (JOSEException | URISyntaxException e) {
            throw new AtbashUnexpectedException(e);

        }
        return result;
    }
}
