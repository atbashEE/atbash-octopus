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

package be.atbash.ee.oauth2.sdk.token;


import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the refresh token class.
 */
public class RefreshTokenTest {

	@Test
	public void testValueConstructor() {

		RefreshToken rt = new RefreshToken("abc");
		assertThat(rt.getValue()).isEqualTo("abc");
		assertThat(rt.getParameterNames()).contains("refresh_token");
		assertThat(rt.getParameterNames()).hasSize(1);
	}

	@Test
	public void testGeneratorConstructor() {

		RefreshToken rt = new RefreshToken(16);
		assertThat(new Base64Value(rt.getValue()).decode().length).isEqualTo(16);
		assertThat(rt.getParameterNames()).contains("refresh_token");
		assertThat(rt.getParameterNames()).hasSize(1);
	}
}
