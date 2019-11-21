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

package be.atbash.ee.oauth2.sdk.auth;


import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests client authentication method class.
 */
public class ClientAuthenticationMethodTest {

    @Test
    public void testConstants() {

        assertThat(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()).isEqualTo("client_secret_basic");
        assertThat(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue()).isEqualTo("client_secret_post");
        assertThat(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue()).isEqualTo("client_secret_jwt");
        assertThat(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue()).isEqualTo("private_key_jwt");
        assertThat(ClientAuthenticationMethod.TLS_CLIENT_AUTH.getValue()).isEqualTo("tls_client_auth");
        assertThat(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.getValue()).isEqualTo("self_signed_tls_client_auth");
        assertThat(ClientAuthenticationMethod.NONE.getValue()).isEqualTo("none");
    }

    @Test
    public void testGetDefault() {

        assertThat(ClientAuthenticationMethod.getDefault()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    @Test
    public void testParse() {

        assertThat(ClientAuthenticationMethod.parse("client_secret_basic")).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(ClientAuthenticationMethod.parse("client_secret_post")).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_POST);
        assertThat(ClientAuthenticationMethod.parse("client_secret_jwt")).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
        assertThat(ClientAuthenticationMethod.parse("private_key_jwt")).isEqualTo(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        assertThat(ClientAuthenticationMethod.parse("tls_client_auth")).isEqualTo(ClientAuthenticationMethod.TLS_CLIENT_AUTH);
        assertThat(ClientAuthenticationMethod.parse("self_signed_tls_client_auth")).isEqualTo(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);
        assertThat(ClientAuthenticationMethod.parse("none")).isEqualTo(ClientAuthenticationMethod.NONE);
    }

    @Test
    public void testParseNull() {

        try {
            ClientAuthenticationMethod.parse(null);
            fail();
        } catch (NullPointerException e) {
            //  ok
        }
    }

    @Test
    public void testParseEmptyValue() {

        try {
            ClientAuthenticationMethod.parse("");
            fail();
        } catch (IllegalArgumentException e) {
            // ok
        }
    }
}
