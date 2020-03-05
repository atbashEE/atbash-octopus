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
package be.atbash.ee.oauth2.sdk.pkce;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Code challenge test.
 */
public class CodeChallengeTest  {

	@Test
	public void testComputePlain()
		throws OAuth2JSONParseException {

		CodeVerifier verifier = new CodeVerifier();

		CodeChallenge challenge = CodeChallenge.compute(CodeChallengeMethod.PLAIN, verifier);

		assertThat(challenge.getValue()).isEqualTo(verifier.getValue());
		
		assertThat(CodeChallenge.parse(challenge.getValue()).getValue()).isEqualTo(challenge.getValue());
	}

	@Test
	public void testS256() {
		// see https://tools.ietf.org/html/rfc7636#appendix-A

		CodeVerifier verifier = new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

		CodeChallenge challenge = CodeChallenge.compute(CodeChallengeMethod.S256, verifier);

		assertThat(challenge.getValue()).isEqualTo("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
	}

	@Test
	public void testUnsupportedMethod() {

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
                CodeChallenge.compute(new CodeChallengeMethod("S512"), new CodeVerifier()));

        assertThat(exception.getMessage()).isEqualTo("Unsupported code challenge method: S512");

    }

	@Test
	public void testParseNull() {

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> CodeChallenge.parse(null));
        assertThat(exception.getMessage()).isEqualTo("Invalid code challenge: The value must not be null or empty string");
    }

	@Test
	public void testParseEmpty() {

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> CodeChallenge.parse(""));

        assertThat(exception.getMessage()).isEqualTo("Invalid code challenge: The value must not be null or empty string");

    }

	@Test
	public void testEnsurePrivateConstructor() {
		
		Constructor[] constructors = CodeChallenge.class.getDeclaredConstructors();
		assertThat(constructors[0].isAccessible()).isFalse();
		assertThat(constructors.length).isEqualTo(1);
	}
}
