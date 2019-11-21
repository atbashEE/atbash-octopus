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

package be.atbash.ee.oauth2.sdk.auth.verifier;


import be.atbash.ee.oauth2.sdk.ErrorObject;
import be.atbash.ee.oauth2.sdk.GeneralException;
import be.atbash.ee.oauth2.sdk.OAuth2Error;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


public class InvalidClientExceptionTest {

    @Test
    public void testInheritance() {

        assertThat(InvalidClientException.BAD_ID).isInstanceOf(GeneralException.class);
    }

    @Test
    public void testStatic() {

        assertThat(InvalidClientException.BAD_ID.getMessage()).isEqualTo("Bad client ID");
        assertThat(InvalidClientException.NOT_REGISTERED_FOR_AUTH_METHOD.getMessage()).isEqualTo("The client is not registered for the requested authentication method");
        assertThat(InvalidClientException.NO_REGISTERED_SECRET.getMessage()).isEqualTo("The client has no registered secret");
        assertThat(InvalidClientException.NO_REGISTERED_JWK_SET.getMessage()).isEqualTo("The client has no registered JWK set");
        assertThat(InvalidClientException.EXPIRED_SECRET.getMessage()).isEqualTo("Expired client secret");
        assertThat(InvalidClientException.BAD_SECRET.getMessage()).isEqualTo("Bad client secret");
        assertThat(InvalidClientException.BAD_JWT_HMAC.getMessage()).isEqualTo("Bad JWT HMAC");
        assertThat(InvalidClientException.NO_MATCHING_JWK.getMessage()).isEqualTo("No matching JWKs found");
        assertThat(InvalidClientException.BAD_JWT_SIGNATURE.getMessage()).isEqualTo("Bad JWT signature");
        assertThat(InvalidClientException.BAD_SELF_SIGNED_CLIENT_CERTIFICATE.getMessage()).isEqualTo("Couldn't validate client X.509 certificate signature: No matching registered client JWK found");
    }

    @Test
    public void testConstructor() {

        InvalidClientException e = new InvalidClientException("message");
        assertThat(e.getMessage()).isEqualTo("message");
    }

    @Test
    public void testToInvalidClientErrorObject() {

        ErrorObject error = new InvalidClientException("message").getErrorObject();
        assertThat(error.getCode()).isEqualTo(OAuth2Error.INVALID_CLIENT.getCode());
        assertThat(error.getDescription()).isEqualTo(OAuth2Error.INVALID_CLIENT.getDescription());
        assertThat(error.getURI()).isNull();
    }
}
