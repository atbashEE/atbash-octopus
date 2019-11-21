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



import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the SAML 2.0 bearer grant.
 */
public class SAML2BearerGrantTest  {

	@Test
	public void testConstructorAndParser()
		throws Exception {

		Base64URLValue assertion = new Base64URLValue("abc"); // dummy XML assertion

		SAML2BearerGrant grant = new SAML2BearerGrant(assertion);
		assertThat(grant.getType()).isEqualTo(GrantType.SAML2_BEARER);
		assertThat(grant.getSAML2Assertion()).isEqualTo(assertion);
		assertThat(grant.getAssertion()).isEqualTo("abc");

		Map<String, List<String>> params = grant.toParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.SAML2_BEARER.getValue()));
		assertThat(params.get("assertion")).isEqualTo(Collections.singletonList("abc"));
		assertThat(params).hasSize(2);

		grant = SAML2BearerGrant.parse(params);
		assertThat(grant.getType()).isEqualTo(GrantType.SAML2_BEARER);
		assertThat(grant.getSAML2Assertion().toString()).isEqualTo("abc");
		assertThat(grant.getAssertion()).isEqualTo("abc");
	}
}
