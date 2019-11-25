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
package be.atbash.ee.oauth2.sdk.id;


import org.junit.Test;

import java.io.Serializable;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the base Identifier class.
 */
public class IdentifierTest  {

	@Test
	public void testConstant() {
		
		assertThat(Identifier.DEFAULT_BYTE_LENGTH).isEqualTo(32);
	}

	@Test
	public void testForSerializableInstance() {

		assertThat((new Identifier() {

			public boolean equals(final Object object) {
				return true;
			}

		})).isInstanceOf(Serializable.class);
	}
}