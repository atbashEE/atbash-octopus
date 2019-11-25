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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.AuthorizationErrorResponse;
import be.atbash.ee.oauth2.sdk.ErrorObject;
import be.atbash.ee.oauth2.sdk.OAuth2Error;
import be.atbash.ee.oauth2.sdk.ResponseMode;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import org.junit.Test;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


public class AuthenticationErrorResponseTest {

    @Test
    public void testStandardErrors() {

        Set<ErrorObject> stdErrors = AuthenticationErrorResponse.getStandardErrors();

        assertThat(stdErrors.contains(OIDCError.INTERACTION_REQUIRED)).isTrue();
        assertThat(stdErrors.contains(OIDCError.LOGIN_REQUIRED)).isTrue();
        assertThat(stdErrors.contains(OIDCError.ACCOUNT_SELECTION_REQUIRED)).isTrue();
        assertThat(stdErrors.contains(OIDCError.CONSENT_REQUIRED)).isTrue();
        assertThat(stdErrors.contains(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS)).isTrue();
        assertThat(stdErrors.contains(OIDCError.REGISTRATION_NOT_SUPPORTED)).isTrue();

        int numAuthzResponseErrors = AuthorizationErrorResponse.getStandardErrors().size();

        assertThat(AuthenticationErrorResponse.getStandardErrors().size() - numAuthzResponseErrors).isEqualTo(6);
    }

    @Test
    public void testCodeErrorResponse()
            throws Exception {

        URI redirectURI = new URI("https://client.com/cb");
        ErrorObject error = OAuth2Error.ACCESS_DENIED;
        State state = new State("123");

        AuthenticationErrorResponse response = new AuthenticationErrorResponse(
                redirectURI, error, state, ResponseMode.QUERY);

        assertThat(response.indicatesSuccess()).isFalse();
        assertThat(response.getRedirectionURI()).isEqualTo(redirectURI);
        assertThat(response.getErrorObject()).isEqualTo(error);
        assertThat(response.getResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(response.getState()).isEqualTo(state);

        URI responseURI = response.toURI();

        String[] parts = responseURI.toString().split("\\?");
        assertThat(parts[0]).isEqualTo(redirectURI.toString());

        assertThat(responseURI.getQuery()).isNotNull();
        assertThat(responseURI.getFragment()).isNull();

        response = AuthenticationErrorResponse.parse(responseURI);

        assertThat(response.indicatesSuccess()).isFalse();
        assertThat(response.getRedirectionURI()).isEqualTo(redirectURI);
        assertThat(response.getErrorObject()).isEqualTo(error);
        assertThat(response.getState()).isEqualTo(state);
        assertThat(response.getResponseMode()).isNull();
        assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
    }

    @Test
    public void testIDTokenErrorResponse()
            throws Exception {

        URI redirectURI = new URI("https://client.com/cb");
        ErrorObject error = OAuth2Error.ACCESS_DENIED;
        State state = new State("123");

        AuthenticationErrorResponse response = new AuthenticationErrorResponse(
                redirectURI, error, state, ResponseMode.FRAGMENT);

        assertThat(response.indicatesSuccess()).isFalse();
        assertThat(response.getRedirectionURI()).isEqualTo(redirectURI);
        assertThat(response.getErrorObject()).isEqualTo(error);
        assertThat(response.getResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
        assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
        assertThat(response.getState()).isEqualTo(state);

        URI responseURI = response.toURI();

        String[] parts = responseURI.toString().split("#");
        assertThat(parts[0]).isEqualTo(redirectURI.toString());

        assertThat(responseURI.getQuery()).isNull();
        assertThat(responseURI.getFragment()).isNotNull();

        response = AuthenticationErrorResponse.parse(responseURI);

        assertThat(response.indicatesSuccess()).isFalse();
        assertThat(response.getRedirectionURI()).isEqualTo(redirectURI);
        assertThat(response.getErrorObject()).isEqualTo(error);
        assertThat(response.getState()).isEqualTo(state);
        assertThat(response.getResponseMode()).isNull();
        assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
    }

    @Test
    public void testRedirectionURIWithQueryString()
            throws Exception {
        // See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/140

        URI redirectURI = URI.create("https://example.com/myservice/?action=oidccallback");
        assertThat(redirectURI.getQuery()).isEqualTo("action=oidccallback");

        State state = new State();

        ErrorObject error = OAuth2Error.ACCESS_DENIED;

        AuthenticationErrorResponse response = new AuthenticationErrorResponse(redirectURI, error, state, ResponseMode.QUERY);

        Map<String, List<String>> params = response.toParameters();
        assertThat(params.get("error")).isEqualTo(Collections.singletonList(OAuth2Error.ACCESS_DENIED.getCode()));
        assertThat(params.get("error_description")).isEqualTo(Collections.singletonList(OAuth2Error.ACCESS_DENIED.getDescription()));
        assertThat(params.get("state")).isEqualTo(Collections.singletonList(state.getValue()));
        assertThat(params).hasSize(3);

        URI uri = response.toURI();

        params = URLUtils.parseParameters(uri.getQuery());
        assertThat(params.get("action")).isEqualTo(Collections.singletonList("oidccallback"));
        assertThat(params.get("error")).isEqualTo(Collections.singletonList(OAuth2Error.ACCESS_DENIED.getCode()));
        assertThat(params.get("error_description")).isEqualTo(Collections.singletonList(OAuth2Error.ACCESS_DENIED.getDescription()));
        assertThat(params.get("state")).isEqualTo(Collections.singletonList(state.getValue()));
        assertThat(params).hasSize(4);
    }
}
