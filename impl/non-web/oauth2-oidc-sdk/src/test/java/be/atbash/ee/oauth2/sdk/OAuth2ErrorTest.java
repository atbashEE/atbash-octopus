/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package be.atbash.ee.oauth2.sdk;


import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the OAuth 2.0 error constants.
 */
public class OAuth2ErrorTest {

    @Test
    public void testHTTPStatusCodes() {

        assertThat(OAuth2Error.ACCESS_DENIED.getHTTPStatusCode()).isEqualTo(403);
        assertThat(OAuth2Error.INVALID_CLIENT.getHTTPStatusCode()).isEqualTo(401);
        assertThat(OAuth2Error.INVALID_GRANT.getHTTPStatusCode()).isEqualTo(400);
        assertThat(OAuth2Error.INVALID_REQUEST.getHTTPStatusCode()).isEqualTo(400);
        assertThat(OAuth2Error.INVALID_SCOPE.getHTTPStatusCode()).isEqualTo(400);
        assertThat(OAuth2Error.SERVER_ERROR.getHTTPStatusCode()).isEqualTo(500);
        assertThat(OAuth2Error.TEMPORARILY_UNAVAILABLE.getHTTPStatusCode()).isEqualTo(503);
        assertThat(OAuth2Error.UNAUTHORIZED_CLIENT.getHTTPStatusCode()).isEqualTo(400);
        assertThat(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getHTTPStatusCode()).isEqualTo(400);
        assertThat(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE.getHTTPStatusCode()).isEqualTo(400);
        assertThat(OAuth2Error.INVALID_RESOURCE.getHTTPStatusCode()).isEqualTo(400);
    }

    @Test
    public void testJARErrors() {

        assertThat(OAuth2Error.INVALID_REQUEST_URI.getCode()).isEqualTo("invalid_request_uri");
        assertThat(OAuth2Error.INVALID_REQUEST_URI.getDescription()).isEqualTo("Invalid request URI");
        assertThat(OAuth2Error.INVALID_REQUEST_URI.getURI()).isNull();
        assertThat(OAuth2Error.INVALID_REQUEST_URI.getHTTPStatusCode()).isEqualTo(302);

        assertThat(OAuth2Error.INVALID_REQUEST_OBJECT.getCode()).isEqualTo("invalid_request_object");
        assertThat(OAuth2Error.INVALID_REQUEST_OBJECT.getDescription()).isEqualTo("Invalid request JWT");
        assertThat(OAuth2Error.INVALID_REQUEST_OBJECT.getURI()).isNull();
        assertThat(OAuth2Error.INVALID_REQUEST_OBJECT.getHTTPStatusCode()).isEqualTo(302);

        assertThat(OAuth2Error.REQUEST_URI_NOT_SUPPORTED.getCode()).isEqualTo("request_uri_not_supported");
        assertThat(OAuth2Error.REQUEST_URI_NOT_SUPPORTED.getDescription()).isEqualTo("Request URI parameter not supported");
        assertThat(OAuth2Error.REQUEST_URI_NOT_SUPPORTED.getURI()).isNull();
        assertThat(OAuth2Error.REQUEST_URI_NOT_SUPPORTED.getHTTPStatusCode()).isEqualTo(302);

        assertThat(OAuth2Error.REQUEST_NOT_SUPPORTED.getCode()).isEqualTo("request_not_supported");
        assertThat(OAuth2Error.REQUEST_NOT_SUPPORTED.getDescription()).isEqualTo("Request parameter not supported");
        assertThat(OAuth2Error.REQUEST_NOT_SUPPORTED.getURI()).isNull();
        assertThat(OAuth2Error.REQUEST_NOT_SUPPORTED.getHTTPStatusCode()).isEqualTo(302);
    }

    @Test
    public void testInvalidResourceError() {

        assertThat(OAuth2Error.INVALID_RESOURCE.getCode()).isEqualTo("invalid_resource");
        assertThat(OAuth2Error.INVALID_RESOURCE.getDescription()).isEqualTo("Invalid or unaccepted resource");
        assertThat(OAuth2Error.INVALID_RESOURCE.getHTTPStatusCode()).isEqualTo(400);
    }
}
