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

package be.atbash.ee.oauth2.sdk.client;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.token.BearerTokenError;
import org.junit.Test;

import java.net.URL;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the client delete request.
 */
public class ClientDeleteRequestTest {

    @Test
    public void testParseWithMissingAuthorizationHeader()
            throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.DELETE, new URL("https://c2id.com/client-reg/123"));

        try {
            ClientDeleteRequest.parse(httpRequest);

            fail();

        } catch (OAuth2JSONParseException e) {

            assertThat(e.getErrorObject()).isInstanceOf(BearerTokenError.class);

            BearerTokenError bte = (BearerTokenError) e.getErrorObject();

            assertThat(bte.getHTTPStatusCode()).isEqualTo(401);
            assertThat(bte.getCode()).isNull();
            assertThat(bte.toWWWAuthenticateHeader()).isEqualTo("Bearer");
        }
    }
}
