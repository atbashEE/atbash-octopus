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
package be.atbash.ee.oauth2.sdk;


import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.JsonObject;

import static org.assertj.core.api.Assertions.assertThat;


public class PushedAuthorizationErrorResponseTest {

    @Test
    public void testLifeCycle_withParams() throws OAuth2JSONParseException {

        PushedAuthorizationErrorResponse response = new PushedAuthorizationErrorResponse(OAuth2Error.INVALID_REQUEST);
        assertThat(response.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
        assertThat(response.indicatesSuccess()).isFalse();

        JsonObject params = response.getErrorObject().toJSONObject();
        assertThat(params.getString("error")).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
        assertThat(params.getString("error_description")).isEqualTo(OAuth2Error.INVALID_REQUEST.getDescription());
        assertThat(params).hasSize(2);

        HTTPResponse httpResponse = response.toHTTPResponse();
        assertThat(httpResponse.getStatusCode()).isEqualTo(400);
        assertThat(httpResponse.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_JSON.toString());
        params = httpResponse.getContentAsJSONObject();
        assertThat(params.getString("error")).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
        assertThat(params.getString("error_description")).isEqualTo(OAuth2Error.INVALID_REQUEST.getDescription());
        assertThat(params).hasSize(2);

        response = PushedAuthorizationErrorResponse.parse(httpResponse);
        assertThat(response.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
        assertThat(response.indicatesSuccess()).isFalse();

        params = response.getErrorObject().toJSONObject();
        assertThat(params.getString("error")).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
        assertThat(params.getString("error_description")).isEqualTo(OAuth2Error.INVALID_REQUEST.getDescription());
        assertThat(params).hasSize(2);
    }

    @Test
    public void testLifeCycle_noParams() throws OAuth2JSONParseException {

        PushedAuthorizationErrorResponse response = new PushedAuthorizationErrorResponse(new ErrorObject(null, null, 400));
        assertThat(response.indicatesSuccess()).isFalse();
        assertThat(response.getErrorObject().toParameters().isEmpty()).isTrue();

        HTTPResponse httpResponse = response.toHTTPResponse();
        assertThat(httpResponse.getStatusCode()).isEqualTo(400);
        assertThat(httpResponse.getContentType()).isNull();
        assertThat(httpResponse.getContent()).isNull();

        response = PushedAuthorizationErrorResponse.parse(httpResponse);
        assertThat(response.indicatesSuccess()).isFalse();
        assertThat(response.getErrorObject().toParameters().isEmpty()).isTrue();
    }

    @Test
    public void testRejectNullErrorObject() {

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> new PushedAuthorizationErrorResponse(null));

        assertThat(exception.getMessage()).isEqualTo("The error must not be null");

    }

    @Test
    public void testParse_rejectStatusCodes201_200() {

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> PushedAuthorizationErrorResponse.parse(new HTTPResponse(201)));

        assertThat(exception.getMessage()).isEqualTo("The HTTP status code must be other than 201 and 200");

        exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> PushedAuthorizationErrorResponse.parse(new HTTPResponse(200)));

        assertThat(exception.getMessage()).isEqualTo("The HTTP status code must be other than 201 and 200");
    }

}
