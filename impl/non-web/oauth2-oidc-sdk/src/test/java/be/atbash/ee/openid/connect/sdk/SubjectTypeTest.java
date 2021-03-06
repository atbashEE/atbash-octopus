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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the SubjectType class.
 */
public class SubjectTypeTest {

    @Test
    public void testToString() {

        assertThat(SubjectType.PAIRWISE.toString()).isEqualTo("pairwise");
        assertThat(SubjectType.PUBLIC.toString()).isEqualTo("public");
    }

    @Test
    public void testParse()
            throws Exception {

        assertThat(SubjectType.parse("pairwise")).isEqualTo(SubjectType.PAIRWISE);
        assertThat(SubjectType.parse("public")).isEqualTo(SubjectType.PUBLIC);
    }

    @Test
    public void testParseExceptionNull() {

        Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                SubjectType.parse(null));

    }

    @Test
    public void testParseInvalidConstant() {

        Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                SubjectType.parse("abc"));

    }
}