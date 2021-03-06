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


import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the client credentials grant.
 */
public class ClientCredentialsGrantTest {

	@Test
	public void testConstructor() {

		ClientCredentialsGrant grant = new ClientCredentialsGrant();
		assertThat(grant.getType()).isEqualTo(GrantType.CLIENT_CREDENTIALS);

		Map<String, List<String>> params = grant.toParameters();
		assertThat(MultivaluedMapUtils.getFirstValue(params, "grant_type")).isEqualTo("client_credentials");
		assertThat(params).hasSize(1);
	}

	@Test
	public void testParse()
		throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("client_credentials"));

		ClientCredentialsGrant grant = ClientCredentialsGrant.parse(params);
		assertThat(grant.getType()).isEqualTo(GrantType.CLIENT_CREDENTIALS);
	}

	@Test
	public void testParseMissingGrantType() {

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> ClientCredentialsGrant.parse(new HashMap<>()));

        assertThat(exception.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
        assertThat(exception.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"grant_type\" parameter");

    }

    @Test
    public void testParseInvalidGrantType() {

        Map<String, List<String>> params = new HashMap<>();
        params.put("grant_type", Collections.singletonList("invalid-grant"));

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> ClientCredentialsGrant.parse(params));

        assertThat(exception.getErrorObject().getCode()).isEqualTo(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode());
        assertThat(exception.getErrorObject().getDescription()).isEqualTo("Unsupported grant type: The \"grant_type\" must be client_credentials");

    }
}
