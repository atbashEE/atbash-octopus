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
package be.atbash.ee.oauth2.sdk.device;

import be.atbash.ee.oauth2.sdk.GrantType;
import be.atbash.ee.oauth2.sdk.OAuth2Error;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the device code grant class.
 */
public class DeviceCodeGrantTest  {

	@Test
	public void testConstructor() throws Exception {

		DeviceCode code = new DeviceCode("abc");

		DeviceCodeGrant grant = new DeviceCodeGrant(code);

		assertThat(grant.getDeviceCode()).isEqualTo(code);

		assertThat(grant.getType()).isEqualTo(GrantType.DEVICE_CODE);

		Map<String, List<String>> params = grant.toParameters();
		assertThat(params.get("device_code")).isEqualTo(Collections.singletonList("abc"));
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList("urn:ietf:params:oauth:grant-type:device_code"));
		assertThat(params).hasSize(2);

		grant = DeviceCodeGrant.parse(params);
		assertThat(grant.getDeviceCode()).isEqualTo(code);
		assertThat(grant.getType()).isEqualTo(GrantType.DEVICE_CODE);
	}

	@Test
	public void testParse() throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.DEVICE_CODE.getValue()));
		params.put("device_code", Collections.singletonList("abc"));

		DeviceCodeGrant grant = DeviceCodeGrant.parse(params);

		assertThat(grant.getType()).isEqualTo(GrantType.DEVICE_CODE);
		assertThat(grant.getDeviceCode().getValue()).isEqualTo("abc");
	}

	@Test
	public void testParseMissingGrantType() {

        Map<String, List<String>> params = new HashMap<>();
        params.put("grant_type", null);
        params.put("device_code", Collections.singletonList("abc"));

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> DeviceCodeGrant.parse(params));

        assertThat(exception.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
        assertThat(exception.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"grant_type\" parameter");
        assertThat(exception.getErrorObject().getURI()).isNull();
    }

	@Test
	public void testParseUnsupportedGrant() {

        Map<String, List<String>> params = new HashMap<>();
        params.put("grant_type", Collections.singletonList("no-such-grant"));
        params.put("device_code", Collections.singletonList("abc"));

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> DeviceCodeGrant.parse(params));
        assertThat(exception.getErrorObject().getCode()).isEqualTo(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode());
        assertThat(exception.getErrorObject().getDescription()).isEqualTo("Unsupported grant type: The \"grant_type\" must be urn:ietf:params:oauth:grant-type:device_code");
        assertThat(exception.getErrorObject().getURI()).isNull();

    }

	@Test
	public void testParseMissingCode() {

        Map<String, List<String>> params = new HashMap<>();
        params.put("grant_type", Collections.singletonList(GrantType.DEVICE_CODE.getValue()));
        params.put("device_code", Collections.singletonList(""));

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> DeviceCodeGrant.parse(params));
        assertThat(exception.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
        assertThat(exception.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing or empty \"device_code\" parameter");
        assertThat(exception.getErrorObject().getURI()).isNull();

    }

	@Test
	public void testEquality() {

		assertThat(new DeviceCodeGrant(new DeviceCode("xyz"))
		                .equals(new DeviceCodeGrant(new DeviceCode("xyz")))).isTrue();
	}

	@Test
	public void testInequality() {

		assertThat(new DeviceCodeGrant(new DeviceCode("xyz"))
		                .equals(new DeviceCodeGrant(new DeviceCode("abc")))).isFalse();
	}
}
