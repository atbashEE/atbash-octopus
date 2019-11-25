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


import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertNotEquals;


public class ErrorObjectTest {

	@Test
	public void testConstructor1() {

		ErrorObject eo = new ErrorObject("access_denied");

		assertThat(eo.getCode()).isEqualTo("access_denied");
		assertThat(eo.getDescription()).isNull();
		assertThat(eo.getURI()).isNull();
		assertThat(eo.getHTTPStatusCode()).isEqualTo(0);

		assertThat(eo.toJSONObject().getString("error")).isEqualTo("access_denied");
		assertThat(eo.toJSONObject()).hasSize(1);
		
		assertThat(MultivaluedMapUtils.getFirstValue(eo.toParameters(), "error")).isEqualTo("access_denied");
		assertThat(eo.toParameters()).hasSize(1);
	}

	@Test
	public void testConstructor2() {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied");

		assertThat(eo.getCode()).isEqualTo("access_denied");
		assertThat(eo.getDescription()).isEqualTo("Access denied");
		assertThat(eo.getURI()).isNull();
		assertThat(eo.getHTTPStatusCode()).isEqualTo(0);

		assertThat(eo.toJSONObject().getString("error")).isEqualTo("access_denied");
		assertThat(eo.toJSONObject().getString("error_description")).isEqualTo("Access denied");
		assertThat(eo.toJSONObject()).hasSize(2);
		
		assertThat(MultivaluedMapUtils.getFirstValue(eo.toParameters(), "error")).isEqualTo("access_denied");
		assertThat(MultivaluedMapUtils.getFirstValue(eo.toParameters(), "error_description")).isEqualTo("Access denied");
		assertThat(eo.toParameters()).hasSize(2);
	}

	@Test
	public void testConstructor3() {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied", 403);

		assertThat(eo.getCode()).isEqualTo("access_denied");
		assertThat(eo.getDescription()).isEqualTo("Access denied");
		assertThat(eo.getURI()).isNull();
		assertThat(eo.getHTTPStatusCode()).isEqualTo(403);

		assertThat(eo.toJSONObject().getString("error")).isEqualTo("access_denied");
		assertThat(eo.toJSONObject().getString("error_description")).isEqualTo("Access denied");
		assertThat(eo.toJSONObject()).hasSize(2);
	}

	@Test
	public void testConstructor4()
		throws Exception {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied", 403, new URI("https://c2id.com/errors/access_denied"));

		assertThat(eo.getCode()).isEqualTo("access_denied");
		assertThat(eo.getDescription()).isEqualTo("Access denied");
		assertThat(eo.getURI()).isEqualTo(new URI("https://c2id.com/errors/access_denied"));
		assertThat(eo.getHTTPStatusCode()).isEqualTo(403);

		assertThat(eo.toJSONObject().getString("error")).isEqualTo("access_denied");
		assertThat(eo.toJSONObject().getString("error_description")).isEqualTo("Access denied");
		assertThat(eo.toJSONObject().getString("error_uri")).isEqualTo("https://c2id.com/errors/access_denied");
		assertThat(eo.toJSONObject()).hasSize(3);
		
		assertThat(MultivaluedMapUtils.getFirstValue(eo.toParameters(), "error")).isEqualTo("access_denied");
		assertThat(MultivaluedMapUtils.getFirstValue(eo.toParameters(), "error_description")).isEqualTo("Access denied");
		assertThat(MultivaluedMapUtils.getFirstValue(eo.toParameters(), "error_uri")).isEqualTo("https://c2id.com/errors/access_denied");
		assertThat(eo.toParameters()).hasSize(3);
	}

	@Test
	public void testParseFull_httpRequest() {

		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		JsonObjectBuilder jsonObject = Json.createObjectBuilder();
		jsonObject.add("error", "access_denied");
		jsonObject.add("error_description", "Access denied");
		jsonObject.add("error_uri", "https://c2id.com/errors/access_denied");

		httpResponse.setContent(jsonObject.build().toString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertThat(errorObject.getHTTPStatusCode()).isEqualTo(403);
		assertThat(errorObject.getCode()).isEqualTo("access_denied");
		assertThat(errorObject.getDescription()).isEqualTo("Access denied");
		assertThat(errorObject.getURI().toString()).isEqualTo("https://c2id.com/errors/access_denied");
	}

	@Test
	public void testParseWithOmittedURI_httpRequest() {

		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		JsonObjectBuilder jsonObject = Json.createObjectBuilder();
		jsonObject.add("error", "access_denied");
		jsonObject.add("error_description", "Access denied");

		httpResponse.setContent(jsonObject.build().toString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertThat(errorObject.getHTTPStatusCode()).isEqualTo(403);
		assertThat(errorObject.getCode()).isEqualTo("access_denied");
		assertThat(errorObject.getDescription()).isEqualTo("Access denied");
		assertThat(errorObject.getURI()).isNull();
	}

	@Test
	public void testParseWithCodeOnly_httpRequest() {

		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		JsonObjectBuilder jsonObject = Json.createObjectBuilder();
		jsonObject.add("error", "access_denied");

		httpResponse.setContent(jsonObject.build().toString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertThat(errorObject.getHTTPStatusCode()).isEqualTo(403);
		assertThat(errorObject.getCode()).isEqualTo("access_denied");
		assertThat(errorObject.getDescription()).isNull();
		assertThat(errorObject.getURI()).isNull();
	}

	@Test
	public void testParseNone_httpRequest() {
		
		HTTPResponse httpResponse = new HTTPResponse(403);
		
		ErrorObject errorObject = ErrorObject.parse(httpResponse);
		
		assertThat(errorObject.getHTTPStatusCode()).isEqualTo(403);
		assertThat(errorObject.getCode()).isNull();
		assertThat(errorObject.getDescription()).isNull();
		assertThat(errorObject.getURI()).isNull();
	}

	@Test
	public void testParseFull_params() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("error", Collections.singletonList("access_denied"));
		params.put("error_description", Collections.singletonList("Access denied"));
		params.put("error_uri", Collections.singletonList("https://c2id.com/errors/access_denied"));
		

		ErrorObject errorObject = ErrorObject.parse(params);

		assertThat(errorObject.getHTTPStatusCode()).isEqualTo(0);
		assertThat(errorObject.getCode()).isEqualTo("access_denied");
		assertThat(errorObject.getDescription()).isEqualTo("Access denied");
		assertThat(errorObject.getURI().toString()).isEqualTo("https://c2id.com/errors/access_denied");
	}

	@Test
	public void testParseWithOmittedURI_params() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("error", Collections.singletonList("access_denied"));
		params.put("error_description", Collections.singletonList("Access denied"));

		ErrorObject errorObject = ErrorObject.parse(params);

		assertThat(errorObject.getHTTPStatusCode()).isEqualTo(0);
		assertThat(errorObject.getCode()).isEqualTo("access_denied");
		assertThat(errorObject.getDescription()).isEqualTo("Access denied");
		assertThat(errorObject.getURI()).isNull();
	}

	@Test
	public void testParseWithCodeOnly_params() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("error", Collections.singletonList("access_denied"));

		ErrorObject errorObject = ErrorObject.parse(params);

		assertThat(errorObject.getHTTPStatusCode()).isEqualTo(0);
		assertThat(errorObject.getCode()).isEqualTo("access_denied");
		assertThat(errorObject.getDescription()).isNull();
		assertThat(errorObject.getURI()).isNull();
	}

	@Test
	public void testParseNone_params() {
		
		ErrorObject errorObject = ErrorObject.parse(new HashMap<String, List<String>>());

		assertThat(errorObject.getHTTPStatusCode()).isEqualTo(0);
		assertThat(errorObject.getCode()).isNull();
		assertThat(errorObject.getDescription()).isNull();
		assertThat(errorObject.getURI()).isNull();
	}

	@Test
	public void testEquality() {
		
		assertThat(OAuth2Error.INVALID_GRANT).isEqualTo(new ErrorObject("invalid_grant", null, 400));
		assertThat(OAuth2Error.INVALID_GRANT).isEqualTo(new ErrorObject("invalid_grant", null, 0));
		assertThat(new ErrorObject(null, null, 0)).isEqualTo(new ErrorObject(null, null, 0));
	}

	@Test
	public void testInequality() {
		
		assertNotEquals(new ErrorObject("bad_request", null, 400), OAuth2Error.INVALID_GRANT);
		assertNotEquals(new ErrorObject("bad_request", null, 0), OAuth2Error.INVALID_GRANT);
	}

	@Test
	public void testSetDescription() {

		assertThat(new ErrorObject("bad_request", "old description").setDescription("new description").getDescription()).isEqualTo("new description");
	}

	@Test
	public void testAppendDescription() {

		assertThat(new ErrorObject("bad_request", "a").appendDescription(" b").getDescription()).isEqualTo("a b");
	}

	@Test
	public void testSetHTTPStatusCode() {

		assertThat(new ErrorObject("code", "description", 400).setHTTPStatusCode(440).getHTTPStatusCode()).isEqualTo(440);
	}
}
