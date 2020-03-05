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
package be.atbash.ee.security.octopus.util.pattern;

import be.atbash.util.exception.AtbashIllegalActionException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class AntPathMatcherTest {

    private AntPathMatcher patternMatcher = new AntPathMatcher();

    @Test
    public void matchStart() {
        assertThat(patternMatcher.matches("com/t?st.jsp", "com/test.jsp")).isTrue();
        assertThat(patternMatcher.matches("com/t?st.jsp", "com/tast.jsp")).isTrue();
        assertThat(patternMatcher.matches("com/t?st.jsp", "com/txst.jsp")).isTrue();

        //
        assertThat(patternMatcher.matches("com/*.jsp", "com/hallo.jsp")).isTrue();
        assertThat(patternMatcher.matches("com/*.jsp", "be/hallo.jsp")).isFalse();

        //
        assertThat(patternMatcher.matches("be/**/test.jsp", "be/atbash/test.jsp")).isTrue();
        assertThat(patternMatcher.matches("be/**/test.jsp", "be/atbash/hello.jsp")).isFalse();

        //
        assertThat(patternMatcher.matches("be/**/servlet/test.jsp", "be/atbash/servlet/test.jsp")).isTrue();
        assertThat(patternMatcher.matches("be/**/servlet/test.jsp", "be/atbash/servlet/hello.jsp")).isFalse();
        assertThat(patternMatcher.matches("be/**/servlet/test.jsp", "be/atbash/other/test.jsp")).isFalse();
    }

    @Test
    public void matchStart_emptyPattern() {
        assertThat(patternMatcher.matches(null, "com/test.jsp")).isFalse();
    }

    @Test
    public void matchStart_emptyPath1() {
        Assertions.assertThrows(AtbashIllegalActionException.class, () -> patternMatcher.matches("be/**/test.jsp", ""));
    }

    @Test
    public void matchStart_emptyPath2() {
        Assertions.assertThrows(AtbashIllegalActionException.class, () -> patternMatcher.matches("be/**/test.jsp", null));
    }

    @Test
    public void matchStart_emptyPath3() {
        Assertions.assertThrows(AtbashIllegalActionException.class, () -> patternMatcher.matches("be/**/test.jsp", "  "));
    }

    @Test
    public void matchStart_pathHasPatternCharacters1() {
        Assertions.assertThrows(AtbashIllegalActionException.class, () -> patternMatcher.matches("be/**/test.jsp", "test*.jsp"));
    }

    @Test
    public void matchStart_pathHasPatternCharacters2() {
        Assertions.assertThrows(AtbashIllegalActionException.class, () -> patternMatcher.matches("be/**/test.jsp", "test?.jsp"));
    }
}
