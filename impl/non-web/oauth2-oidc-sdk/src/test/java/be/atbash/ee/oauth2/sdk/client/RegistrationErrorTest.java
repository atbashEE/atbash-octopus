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
package be.atbash.ee.oauth2.sdk.client;


import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the registration error constants.
 */
public class RegistrationErrorTest {

	@Test
	public void testConstants() {

		// http://tools.ietf.org/html/draft-ietf-oauth-dyn-reg-17#section-4.2

		assertThat(RegistrationError.INVALID_REDIRECT_URI.getCode()).isEqualTo("invalid_redirect_uri");
		assertThat(RegistrationError.INVALID_CLIENT_METADATA.getCode()).isEqualTo("invalid_client_metadata");
		assertThat(RegistrationError.INVALID_SOFTWARE_STATEMENT.getCode()).isEqualTo("invalid_software_statement");
		assertThat(RegistrationError.UNAPPROVED_SOFTWARE_STATEMENT.getCode()).isEqualTo("unapproved_software_statement");
	}
}
