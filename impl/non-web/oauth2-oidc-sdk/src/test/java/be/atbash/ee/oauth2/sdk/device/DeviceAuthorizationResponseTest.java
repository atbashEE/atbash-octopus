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

import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class DeviceAuthorizationResponseTest{

	@Test
	public void testRegisteredParameters() {

		assertThat(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames()).contains("device_code");
		assertThat(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames()).contains("user_code");
		assertThat(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames()).contains("verification_uri");
		assertThat(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames()).contains("verification_uri_complete");
		assertThat(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames()).contains("expires_in");
		assertThat(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames()).contains("interval");
		assertThat(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames()).hasSize(6);
	}

	@Test
	public void testMinimalSuccess() throws Exception {

		DeviceCode deviceCode = new DeviceCode();
		UserCode userCode = new UserCode();
		URI verificationUri = new URI("https://c2id.com/devauthz/");
		long lifetime = 1800;

		DeviceAuthorizationSuccessResponse resp = new DeviceAuthorizationSuccessResponse(deviceCode, userCode,
		                verificationUri, lifetime);

		assertThat(resp.getDeviceCode()).isEqualTo(deviceCode);
		assertThat(resp.getUserCode()).isEqualTo(userCode);
		assertThat(resp.getVerificationUri()).isEqualTo(verificationUri);
		assertThat(resp.getLifetime()).isEqualTo(lifetime);

		assertThat(resp.getVerificationUriComplete()).isEqualTo(null);
		assertThat(resp.getInterval()).isEqualTo(5);

		assertThat(resp.getCustomParameters().isEmpty()).isTrue();

		HTTPResponse httpResp = resp.toHTTPResponse();
		JsonObject params = httpResp.getContentAsJSONObject();
		assertThat(params.getString("device_code")).isEqualTo(deviceCode.getValue());
		assertThat(params.getString("user_code")).isEqualTo(userCode.getValue());
		assertThat(params.getString("verification_uri")).isEqualTo(verificationUri.toString());
		assertThat(params.containsKey("verification_uri_complete")).isFalse();
		assertThat(params.getJsonNumber("expires_in").longValue()).isEqualTo(lifetime);
		assertThat(params.getJsonNumber("interval").longValue()).isEqualTo(5L);
		assertThat(params).hasSize(5);

		resp = DeviceAuthorizationResponse.parse(httpResp).toSuccessResponse();

		assertThat(resp.getDeviceCode()).isEqualTo(deviceCode);
		assertThat(resp.getUserCode()).isEqualTo(userCode);
		assertThat(resp.getVerificationUri()).isEqualTo(verificationUri);
		assertThat(resp.getLifetime()).isEqualTo(lifetime);

		assertThat(resp.getVerificationUriComplete()).isEqualTo(null);
		assertThat(resp.getInterval()).isEqualTo(5);

		assertThat(resp.getCustomParameters().isEmpty()).isTrue();
	}

	@Test
	public void testFull() throws Exception {

		DeviceCode deviceCode = new DeviceCode();
		UserCode userCode = new UserCode();
		URI verificationUri = new URI("https://c2id.com/devauthz/");
		URI verificationUriComplete = new URI("https://c2id.com/devauthz/complete");
		long lifetime = 3600;
		long interval = 10;

		Map<String, Object> customParams = new HashMap<>();
		customParams.put("x", "100");
		customParams.put("y", "200");
		customParams.put("z", "300");

		DeviceAuthorizationSuccessResponse resp = new DeviceAuthorizationSuccessResponse(deviceCode, userCode,
		                verificationUri, verificationUriComplete, lifetime, interval, customParams);

		assertThat(resp.getDeviceCode()).isEqualTo(deviceCode);
		assertThat(resp.getUserCode()).isEqualTo(userCode);
		assertThat(resp.getVerificationUri()).isEqualTo(verificationUri);
		assertThat(resp.getVerificationUriComplete()).isEqualTo(verificationUriComplete);
		assertThat(resp.getLifetime()).isEqualTo(lifetime);
		assertThat(resp.getInterval()).isEqualTo(interval);
		assertThat(resp.getCustomParameters().get("x")).isEqualTo("100");
		assertThat(resp.getCustomParameters().get("y")).isEqualTo("200");
		assertThat(resp.getCustomParameters().get("z")).isEqualTo("300");
		assertThat(resp.getCustomParameters()).hasSize(3);

		HTTPResponse httpResp = resp.toHTTPResponse();
		JsonObject params = httpResp.getContentAsJSONObject();
		assertThat(params.getString("device_code")).isEqualTo(deviceCode.getValue());
		assertThat(params.getString("user_code")).isEqualTo(userCode.getValue());
		assertThat(params.getString("verification_uri")).isEqualTo(verificationUri.toString());
		assertThat(params.getString("verification_uri_complete")).isEqualTo(verificationUriComplete.toString());
		assertThat(params.getJsonNumber("expires_in").longValue()).isEqualTo(lifetime);
		assertThat(params.getJsonNumber("interval").longValue()).isEqualTo(interval);
		assertThat(params.getString("x")).isEqualTo("100");
		assertThat(params.getString("y")).isEqualTo("200");
		assertThat(params.getString("z")).isEqualTo("300");
		assertThat(params).hasSize(9);

		resp = DeviceAuthorizationResponse.parse(httpResp).toSuccessResponse();

		assertThat(resp.getDeviceCode()).isEqualTo(deviceCode);
		assertThat(resp.getUserCode()).isEqualTo(userCode);
		assertThat(resp.getVerificationUri()).isEqualTo(verificationUri);
		assertThat(resp.getVerificationUriComplete()).isEqualTo(verificationUriComplete);
		assertThat(resp.getLifetime()).isEqualTo(lifetime);
		assertThat(resp.getInterval()).isEqualTo(interval);
		assertThat(resp.getCustomParameters().get("x")).isEqualTo("100");
		assertThat(resp.getCustomParameters().get("y")).isEqualTo("200");
		assertThat(resp.getCustomParameters().get("z")).isEqualTo("300");
		assertThat(resp.getCustomParameters()).hasSize(3);
	}

	@Test
	public void testConstructParseExceptionMissingDeviceCode() throws Exception {

        DeviceCode deviceCode = null;
        UserCode userCode = new UserCode();
        URI verificationUri = new URI("https://c2id.com/devauthz/");
        long lifetime = 3600;

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> new DeviceAuthorizationSuccessResponse(deviceCode, userCode, verificationUri, lifetime));
        assertThat(exception.getMessage()).isEqualTo("The device_code must not be null");

        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("user_code", userCode.getValue());
        builder.add("verification_uri", verificationUri.toString());
        builder.add("expires_in", lifetime);

        HTTPResponse httpResponse = new HTTPResponse(200);
        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpResponse.setCacheControl("no-store");
        httpResponse.setPragma("no-cache");
        httpResponse.setContent(builder.build().toString());

        OAuth2JSONParseException exception1 = Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                DeviceAuthorizationSuccessResponse.parse(httpResponse));

        assertThat(exception1.getMessage()).isEqualTo("Missing JSON object member with key \"device_code\"");

    }

	@Test
	public void testConstructParseExceptionMissingUserCode() throws Exception {

        DeviceCode deviceCode = new DeviceCode();
        UserCode userCode = null;
        URI verificationUri = new URI("https://c2id.com/devauthz/");
        long lifetime = 3600;

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
                new DeviceAuthorizationSuccessResponse(deviceCode, userCode, verificationUri, lifetime));

        assertThat(exception.getMessage()).isEqualTo("The user_code must not be null");


        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("device_code", deviceCode.getValue());
        builder.add("verification_uri", verificationUri.toString());
        builder.add("expires_in", lifetime);

        HTTPResponse httpResponse = new HTTPResponse(200);
        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpResponse.setCacheControl("no-store");
        httpResponse.setPragma("no-cache");
        httpResponse.setContent(builder.build().toString());

        OAuth2JSONParseException exception1 = Assertions.assertThrows(OAuth2JSONParseException.class, () -> DeviceAuthorizationSuccessResponse.parse(httpResponse));

        assertThat(exception1.getMessage()).isEqualTo("Missing JSON object member with key \"user_code\"");

    }

    @Test
    public void testConstructParseExceptionMissingVerificationUri() {

        DeviceCode deviceCode = new DeviceCode();
        UserCode userCode = new UserCode();
        URI verificationUri = null;
        long lifetime = 3600;

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
                new DeviceAuthorizationSuccessResponse(deviceCode, userCode, verificationUri, lifetime));

        assertThat(exception.getMessage()).isEqualTo("The verification_uri must not be null");


        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("device_code", deviceCode.getValue());
        builder.add("user_code", userCode.getValue());
        builder.add("expires_in", lifetime);

        HTTPResponse httpResponse = new HTTPResponse(200);
        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpResponse.setCacheControl("no-store");
        httpResponse.setPragma("no-cache");
        httpResponse.setContent(builder.build().toString());

        IllegalArgumentException exception1 = Assertions.assertThrows(IllegalArgumentException.class, () ->
                DeviceAuthorizationSuccessResponse.parse(httpResponse));

        assertThat(exception1.getMessage()).isEqualTo("The verification_uri must not be null");

    }

	@Test
	public void testConstructExceptionLifetime0() throws Exception {

        DeviceCode deviceCode = new DeviceCode();
        UserCode userCode = new UserCode();
        URI verificationUri = new URI("https://c2id.com/devauthz/");
        long lifetime = 0;

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
                new DeviceAuthorizationSuccessResponse(deviceCode, userCode, verificationUri, lifetime));

        assertThat(exception.getMessage()).isEqualTo("The lifetime must be greater than 0");
    }

	@Test
	public void testToErrorResponse() throws Exception {

		DeviceAuthorizationErrorResponse response = new DeviceAuthorizationErrorResponse(
		                DeviceAuthorizationGrantError.AUTHORIZATION_PENDING);

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = DeviceAuthorizationResponse.parse(httpResponse).toErrorResponse();

		assertThat(response.getErrorObject()).isEqualTo(DeviceAuthorizationGrantError.AUTHORIZATION_PENDING);
	}
}
