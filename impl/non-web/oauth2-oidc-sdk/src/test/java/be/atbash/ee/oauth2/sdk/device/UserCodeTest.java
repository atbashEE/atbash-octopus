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
package be.atbash.ee.oauth2.sdk.device;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

/**
 * Tests generation and comparison of user codes
 */
public class UserCodeTest {

    @Test
    public void testValueConstructor() {

        String value = "abc";

        UserCode code = new UserCode(value);

        assertThat(code.getValue()).isEqualTo(value);
        assertThat(code.toString()).isEqualTo(value);
        assertThat(UserCode.LETTER_CHAR_SET).isEqualTo(code.getCharset());
        assertThat(code.getStrippedValue()).isEqualTo("BC");
    }

    @Test
    public void testValueAndCharsetConstructor() {

        String value = "12345678";

        UserCode code = new UserCode(value, UserCode.DIGIT_CHAR_SET);

        assertThat(code.getValue()).isEqualTo(value);
        assertThat(code.toString()).isEqualTo(value);
        assertThat(UserCode.DIGIT_CHAR_SET).isEqualTo(code.getCharset());
        assertThat(code.getStrippedValue()).isEqualTo("12345678");
    }

    @Test
    public void testEmptyValue() {

        try {
            new UserCode("");

            fail("Failed to raise exception");

        } catch (IllegalArgumentException e) {

            // ok
        }
    }

    @Test
    public void testEquality() {

        UserCode c1 = new UserCode("abc", UserCode.LETTER_CHAR_SET);

        UserCode c2 = new UserCode("abc", UserCode.LETTER_CHAR_SET);

        assertThat(c1.equals(c2)).isTrue();
    }

    @Test
    public void testEqualityStripped() {

        UserCode c1 = new UserCode("abc-def", UserCode.LETTER_CHAR_SET);

        UserCode c2 = new UserCode("1ABCDEF8", UserCode.LETTER_CHAR_SET);

        assertThat(c1.equals(c2)).isTrue();
    }

    @Test
    public void testInequality() {

        UserCode c1 = new UserCode("abc", UserCode.LETTER_CHAR_SET);

        UserCode c2 = new UserCode("def", UserCode.LETTER_CHAR_SET);

        assertThat(c1.equals(c2)).isFalse();
    }

    @Test
    public void testInequalityNull() {

        UserCode c1 = new UserCode("abc", UserCode.LETTER_CHAR_SET);

        assertThat(c1.equals(null)).isFalse();
    }

    @Test
    public void testHashCode() {

        UserCode c1 = new UserCode("abc");

        UserCode c2 = new UserCode("abc");

        assertThat(c2.hashCode()).isEqualTo(c1.hashCode());
    }

    @Test
    public void testGeneration() {

        UserCode code = new UserCode();

        System.out.println("Random user code (default length): " + code);

        assertThat(code.toString().length()).isEqualTo(8 + 1);
        assertThat(code.getStrippedValue().length()).isEqualTo(8);
    }

    @Test
    public void testGenerationVarLengthAndCharset() {

        UserCode code = new UserCode(UserCode.DIGIT_CHAR_SET, 16);

        System.out.println("Random user code (16 char length): " + code);

        assertThat(code.toString().length()).isEqualTo(16 + 3);
        assertThat(code.getStrippedValue().length()).isEqualTo(16);
    }

    @Test
    public void testJSONValue() {

        UserCode code = new UserCode("abc");

        String json = code.toJSONString();

        System.out.println("\"user_code\":" + json);

        assertThat(json).isEqualTo("\"abc\"");
    }
}
