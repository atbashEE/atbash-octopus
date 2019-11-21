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


import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class RequestObjectPOSTErrorResponseTest {

    @Test
    public void testLifeCycle() throws OAuth2JSONParseException {

        RequestObjectPOSTErrorResponse errorResponse = new RequestObjectPOSTErrorResponse(HTTPResponse.SC_UNAUTHORIZED);

        assertThat(errorResponse.getHTTPStatusCode()).isEqualTo(HTTPResponse.SC_UNAUTHORIZED);

        assertThat(errorResponse.getErrorObject().getCode()).isNull();
        assertThat(errorResponse.getErrorObject().getDescription()).isNull();
        assertThat(errorResponse.getErrorObject().getHTTPStatusCode()).isEqualTo(HTTPResponse.SC_UNAUTHORIZED);

        HTTPResponse httpResponse = errorResponse.toHTTPResponse();
        assertThat(httpResponse.getStatusCode()).isEqualTo(HTTPResponse.SC_UNAUTHORIZED);
        assertThat(httpResponse.getContentType()).isNull();
        assertThat(httpResponse.getContent()).isNull();

        errorResponse = RequestObjectPOSTErrorResponse.parse(httpResponse);

        assertThat(errorResponse.getHTTPStatusCode()).isEqualTo(HTTPResponse.SC_UNAUTHORIZED);

        assertThat(errorResponse.getErrorObject().getCode()).isNull();
        assertThat(errorResponse.getErrorObject().getDescription()).isNull();
        assertThat(errorResponse.getErrorObject().getHTTPStatusCode()).isEqualTo(HTTPResponse.SC_UNAUTHORIZED);
    }

    @Test
    public void testParseRejectHTTP2xx() {

        for (int statusCode = 200; statusCode < 300; statusCode++) {
            try {
                RequestObjectPOSTErrorResponse.parse(new HTTPResponse(statusCode));
                fail();
            } catch (OAuth2JSONParseException e) {
                assertThat(e.getMessage()).isEqualTo("Unexpected HTTP status code, must not be 2xx");
            }
        }
    }
}
