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
package be.atbash.ee.openid.connect.sdk.op;


import be.atbash.ee.oauth2.sdk.SerializeException;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class OIDCProviderConfigurationRequestTest {

    @Test
    public void testWellKnownPath() {

        assertThat(OIDCProviderConfigurationRequest.OPENID_PROVIDER_WELL_KNOWN_PATH).isEqualTo("/.well-known/openid-configuration");
    }

    @Test
    public void testConstruct() {

        Issuer issuer = new Issuer("https://c2id.com");

        OIDCProviderConfigurationRequest request = new OIDCProviderConfigurationRequest(issuer);

        assertThat(request.getEndpointURI().toString()).isEqualTo("https://c2id.com/.well-known/openid-configuration");

        HTTPRequest httpRequest = request.toHTTPRequest();
        assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.GET);
        assertThat(httpRequest.getURL().toString()).isEqualTo("https://c2id.com/.well-known/openid-configuration");
        assertThat(httpRequest.getHeaderMap().isEmpty()).isTrue();
    }

    @Test
    public void testConstructFromInvalidIssuer() {

        SerializeException exception = Assertions.assertThrows(SerializeException.class, () ->
                new OIDCProviderConfigurationRequest(new Issuer("c2id.com")).toHTTPRequest());

        assertThat(exception.getMessage()).isEqualTo("URI is not absolute");

    }
}
