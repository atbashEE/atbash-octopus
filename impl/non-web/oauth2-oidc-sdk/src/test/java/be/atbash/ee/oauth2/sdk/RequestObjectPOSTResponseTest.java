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
package be.atbash.ee.oauth2.sdk;

import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import org.junit.Test;

import java.net.URI;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;


public class RequestObjectPOSTResponseTest {

    @Test
    public void testParseSuccess()
            throws Exception {

        Issuer issuer = new Issuer("https://c2id.com");
        Audience audience = new Audience("123");
        URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
        long expTs = DateUtils.toSecondsSinceEpoch(new Date());
        Date exp = DateUtils.fromSecondsSinceEpoch(expTs);

        RequestObjectPOSTSuccessResponse response = new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, exp);

        assertThat(response.getIssuer()).isEqualTo(issuer);
        assertThat(response.getAudience()).isEqualTo(audience);
        assertThat(response.getRequestURI()).isEqualTo(requestURI);
        assertThat(response.getExpirationTime()).isEqualTo(exp);

        assertThat(response.indicatesSuccess()).isTrue();

        HTTPResponse httpResponse = response.toHTTPResponse();

        response = RequestObjectPOSTResponse.parse(httpResponse).toSuccessResponse();

        assertThat(response.getIssuer()).isEqualTo(issuer);
        assertThat(response.getAudience()).isEqualTo(audience);
        assertThat(response.getRequestURI()).isEqualTo(requestURI);
        assertThat(response.getExpirationTime()).isEqualTo(exp);

        assertThat(response.indicatesSuccess()).isTrue();
    }

    @Test
    public void testParseError()
            throws Exception {

        RequestObjectPOSTErrorResponse errorResponse = new RequestObjectPOSTErrorResponse(HTTPResponse.SC_UNAUTHORIZED);

        assertThat(errorResponse.getHTTPStatusCode()).isEqualTo(HTTPResponse.SC_UNAUTHORIZED);

        assertThat(errorResponse.getErrorObject().getCode()).isNull();
        assertThat(errorResponse.getErrorObject().getDescription()).isNull();
        assertThat(errorResponse.getErrorObject().getHTTPStatusCode()).isEqualTo(HTTPResponse.SC_UNAUTHORIZED);

        HTTPResponse httpResponse = errorResponse.toHTTPResponse();

        errorResponse = RequestObjectPOSTResponse.parse(httpResponse).toErrorResponse();

        assertThat(errorResponse.getHTTPStatusCode()).isEqualTo(HTTPResponse.SC_UNAUTHORIZED);

        assertThat(errorResponse.getErrorObject().getCode()).isNull();
        assertThat(errorResponse.getErrorObject().getDescription()).isNull();
        assertThat(errorResponse.getErrorObject().getHTTPStatusCode()).isEqualTo(HTTPResponse.SC_UNAUTHORIZED);
    }
}
