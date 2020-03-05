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
package be.atbash.ee.oauth2.sdk.token;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


public class AccessTokenTest {

    @Test
    public void testEquality() {

        AccessToken t1 = new TypelessAccessToken("abc");
        AccessToken t2 = new BearerAccessToken("abc");

        assertThat(t1.equals(t2)).isTrue();
    }

    @Test
    public void testEqualityAlt() {

        assertThat(new TypelessAccessToken("abc").equals(new BearerAccessToken("abc"))).isTrue();
    }

    @Test
    public void testInequality_caseSensitive() {

        AccessToken t1 = new TypelessAccessToken("abc");
        AccessToken t2 = new BearerAccessToken("ABC");

        assertThat(t1.equals(t2)).isFalse();
    }
}
