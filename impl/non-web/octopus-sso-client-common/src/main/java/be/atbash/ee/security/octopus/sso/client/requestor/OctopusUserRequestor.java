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
package be.atbash.ee.security.octopus.sso.client.requestor;

import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.sso.client.OpenIdVariableClientData;
import be.atbash.ee.security.octopus.sso.client.config.OctopusSSOServerClientConfiguration;
import be.atbash.ee.security.octopus.sso.client.debug.CorrelationCounter;
import be.atbash.ee.security.octopus.sso.core.OctopusRetrievalException;
import be.atbash.ee.security.octopus.sso.core.rest.PrincipalUserInfoJSONProvider;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOTokenConverter;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 *
 */
public class OctopusUserRequestor extends AbstractRequestor {

    private OctopusSSOTokenConverter octopusSSOTokenConverter;

    private PrincipalUserInfoJSONProvider userInfoJSONProvider;
    private CustomUserInfoValidator customUserInfoValidator;

    public OctopusUserRequestor(OctopusCoreConfiguration coreConfiguration, OctopusSSOServerClientConfiguration configuration, OctopusSSOTokenConverter octopusSSOTokenConverter, PrincipalUserInfoJSONProvider userInfoJSONProvider
            , CustomUserInfoValidator customUserInfoValidator) {
        setConfiguration(coreConfiguration, configuration);
        this.octopusSSOTokenConverter = octopusSSOTokenConverter;
        this.userInfoJSONProvider = userInfoJSONProvider;
        this.customUserInfoValidator = customUserInfoValidator;
    }

    public OctopusSSOToken getOctopusSSOToken(OpenIdVariableClientData variableClientData, BearerAccessToken accessToken) throws URISyntaxException, ParseException, JOSEException, java.text.ParseException, OctopusRetrievalException {
        // Create UserInfoRequest instance to send request to Server
        UserInfoRequest infoRequest = new UserInfoRequest(new URI(configuration.getUserInfoEndpoint()), accessToken);

        HTTPRequest httpRequest = infoRequest.toHTTPRequest();

        int correlationId = -1;
        if (coreConfiguration.showDebugFor().contains(Debug.SSO_REST)) {
            correlationId = CorrelationCounter.VALUE.getAndIncrement();
            showRequest(correlationId, httpRequest);
        }

        HTTPResponse response;
        try {
            response = httpRequest.send();
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new AtbashUnexpectedException(e);

        }
        if (coreConfiguration.showDebugFor().contains(Debug.SSO_REST)) {
            showResponse(correlationId, response);
        }

        UserInfoResponse userInfoResponse = UserInfoResponse.parse(response);

        if (!userInfoResponse.indicatesSuccess()) {
            UserInfoErrorResponse errorResponse = (UserInfoErrorResponse) userInfoResponse;
            throw new OctopusRetrievalException(errorResponse.getErrorObject());

        }

        UserInfoSuccessResponse successInfoResponse = (UserInfoSuccessResponse) userInfoResponse;

        UserInfo userInfo;
        if (successInfoResponse.getUserInfoJWT() != null) {
            // We have a JWT as response
            SignedJWT signedJWT = (SignedJWT) successInfoResponse.getUserInfoJWT();

            // TODO Support for encryption
            // See also OctopusSSOEndpoint.getUserInfo()
            boolean valid = signedJWT.verify(new MACVerifier(configuration.getSSOIdTokenSecret()));  // TODO Configurable !!
            if (!valid) {
                ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-015", "JWT Signature Validation failed");
                throw new OctopusRetrievalException(errorObject);

            }

            userInfo = new UserInfo(signedJWT.getJWTClaimsSet());
        } else {
            // We have a a JSON as response which are just the claims.
            userInfo = successInfoResponse.getUserInfo();
        }

        // We always use scope 'octopus' so JWT is always signed and according spec, we need iss, aud and added nonce ourself.
        List<String> claimsWithIssue = validateUserInfo(userInfo, variableClientData);

        if (customUserInfoValidator != null) {
            claimsWithIssue = customUserInfoValidator.validateUserInfo(userInfo, variableClientData, claimsWithIssue);
        }

        if (!claimsWithIssue.isEmpty()) {
            StringBuilder claimsWithError = new StringBuilder();
            for (String claim : claimsWithIssue) {
                if (claimsWithError.length() > 0) {
                    claimsWithError.append(", ");
                }
                claimsWithError.append(claim);
            }
            ErrorObject errorObject = new ErrorObject("OCT-SSO-CLIENT-016", "JWT claim Validation failed : " + claimsWithError.toString());
            throw new OctopusRetrievalException(errorObject);

        }

        OctopusSSOToken user = octopusSSOTokenConverter.fromUserInfo(userInfo, userInfoJSONProvider);

        user.setBearerAccessToken(accessToken);
        return user;
    }

    private List<String> validateUserInfo(UserInfo userInfo, OpenIdVariableClientData variableClientData) {
        List<String> result = new ArrayList<>();

        if (variableClientData.getRootURL() != null) {
            if (!variableClientData.getNonce().equals(Nonce.parse(userInfo.getStringClaim("nonce")))) {
                result.add("nonce");
            }
        }

        if (!configuration.getOctopusSSOServer().equals(userInfo.getStringClaim("iss"))) {
            result.add("iss");
        }

        if (userInfo.getDateClaim("exp") == null || userInfo.getDateClaim("exp").before(new Date())) {
            result.add("exp");
        }

        if (variableClientData.getRootURL() != null) {
            if (!configuration.getSSOClientId().equals(userInfo.getStringClaim("aud"))) {
                result.add("aud");
            }
        }

        return result;

    }

}
