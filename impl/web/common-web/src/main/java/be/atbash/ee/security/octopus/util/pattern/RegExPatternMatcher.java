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

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.util.PatternMatcher;

import jakarta.enterprise.inject.Typed;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@code PatternMatcher} implementation that uses standard {@link java.util.regex} objects.
 *
 * @see Pattern
 */
@Typed
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.util.RegExPatternMatcher"})
public class RegExPatternMatcher implements PatternMatcher {

    /**
     * Simple implementation that merely uses the default pattern comparison logic provided by the
     * JDK.
     * <p/>This implementation essentially executes the following:
     * <pre>
     * Pattern p = Pattern.compile(pattern);
     * Matcher m = p.matcher(source);
     * return m.matches();</pre>
     *
     * @param pattern the pattern to match against
     * @param source  the source to match
     * @return {@code true} if the source matches the required pattern, {@code false} otherwise.
     */
    public boolean matches(String pattern, String source) {
        if (pattern == null) {
            throw new IllegalArgumentException("pattern argument cannot be null.");
        }
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(source);
        return m.matches();
    }
}
