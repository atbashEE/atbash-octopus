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


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Code challenge methods test.
 */
public class CodeChallengeMethodTest  {
	
	@Test
	public void testConstants() {

		assertThat(CodeChallengeMethod.PLAIN.getValue()).isEqualTo("plain");
		assertThat(CodeChallengeMethod.S256.getValue()).isEqualTo("S256");
	}

	@Test
	public void testDefault() {

		assertThat(CodeChallengeMethod.PLAIN.equals(CodeChallengeMethod.getDefault())).isTrue();
	}

	@Test
	public void testParse() {

		assertThat(CodeChallengeMethod.PLAIN.equals(CodeChallengeMethod.parse("plain"))).isTrue();
		assertThat(CodeChallengeMethod.S256.equals(CodeChallengeMethod.parse("S256"))).isTrue();
		assertThat(new CodeChallengeMethod("S512").equals(CodeChallengeMethod.parse("S512"))).isTrue();
	}

	@Test
	public void testParseEquality() {

		assertThat(CodeChallengeMethod.parse("plain") == CodeChallengeMethod.PLAIN).isTrue();
		assertThat(CodeChallengeMethod.parse("S256") == CodeChallengeMethod.S256).isTrue();
	}
}
