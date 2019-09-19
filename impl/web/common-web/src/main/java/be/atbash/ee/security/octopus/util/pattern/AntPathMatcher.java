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
package be.atbash.ee.security.octopus.util.pattern;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.util.PatternMatcher;
import be.atbash.util.Reviewed;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;

import javax.enterprise.inject.Typed;

/**
 * <p>PathMatcher implementation for Ant-style path patterns.
 * Examples are provided below.</p>
 * <p>
 * <p>Part of this mapping code has been kindly borrowed from
 * <a href="http://ant.apache.org">Apache Ant</a>.
 * <p>
 * <p>The mapping matches URLs using the following rules:<br>
 * <ul>
 * <li>? matches one character</li>
 * <li>* matches zero or more characters</li>
 * <li>** matches zero or more 'directories' in a path</li>
 * </ul>
 * <p>
 * <p>Some examples:<br>
 * <ul>
 * <li><code>com/t?st.jsp</code> - matches <code>com/test.jsp</code> but also
 * <code>com/tast.jsp</code> or <code>com/txst.jsp</code></li>
 * <li><code>com/*.jsp</code> - matches all <code>.jsp</code> files in the
 * <code>com</code> directory</li>
 * <li><code>com/&#42;&#42;/test.jsp</code> - matches all <code>test.jsp</code>
 * files underneath the <code>com</code> path</li>
 * <li><code>org/apache/shiro/&#42;&#42;/*.jsp</code> - matches all <code>.jsp</code>
 * files underneath the <code>org/apache/shiro</code> path</li>
 * <li><code>org/&#42;&#42;/servlet/bla.jsp</code> - matches
 * <code>org/apache/shiro/servlet/bla.jsp</code> but also
 * <code>org/apache/shiro/testing/servlet/bla.jsp</code> and
 * <code>org/servlet/bla.jsp</code></li>
 * </ul>
 * <p>
 * <p><b>N.B.</b>: This class was borrowed (with much appreciation) from the
 * <a href="http://www.springframework.org">Spring Framework</a> with modifications.  We didn't want to reinvent the
 * wheel of great work they've done, but also didn't want to force every Shiro user to depend on Spring</p>
 * <p>
 * <p>As per the Apache 2.0 license, the original copyright notice and all author and copyright information have
 * remained in tact.</p>
 *
 * @since 16.07.2003
 */
@Typed
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.util.AntPathMatcher"})
@Reviewed
public class AntPathMatcher implements PatternMatcher {

    private static final String PATH_SEPARATOR = "/";

    public boolean matches(String pattern, String path) {
        if (pattern == null) {
            return false;
        }
        if (StringUtils.isEmpty(path)) {
            // TODO Document and supply exception number
            throw new AtbashIllegalActionException("(OCT-DEV-???) Path value is empty");
        }
        if (isPattern(path)) {
            // TODO Document and supply exception number
            throw new AtbashIllegalActionException(String.format("(OCT-DEV-???) Path value contains pattern characters which is not allowed : '%s'", path));
        }
        return doMatch(pattern, path);
    }

    private boolean isPattern(String path) {
        return (path.indexOf('*') != -1 || path.indexOf('?') != -1);
    }

    /**
     * Actually match the given <code>path</code> against the given <code>pattern</code>.
     *
     * @param pattern the pattern to match against
     * @param path    the path String to test
     * @return <code>true</code> if the supplied <code>path</code> matched,
     * <code>false</code> if it didn't
     */
    private boolean doMatch(String pattern, String path) {
        if (path.startsWith(PATH_SEPARATOR) != pattern.startsWith(PATH_SEPARATOR)) {
            return false;
        }

        String[] pattDirs = StringUtils.tokenizeToStringArray(pattern, PATH_SEPARATOR);
        String[] pathDirs = StringUtils.tokenizeToStringArray(path, PATH_SEPARATOR);

        int pattIdxStart = 0;
        int pattIdxEnd = pattDirs.length - 1;
        int pathIdxStart = 0;
        int pathIdxEnd = pathDirs.length - 1;

        // Match all elements up to the first **
        while (pattIdxStart <= pattIdxEnd && pathIdxStart <= pathIdxEnd) {
            String patDir = pattDirs[pattIdxStart];
            if ("**".equals(patDir)) {
                break;
            }
            if (!matchStrings(patDir, pathDirs[pathIdxStart])) {
                return false;
            }
            pattIdxStart++;
            pathIdxStart++;
        }

        if (pathIdxStart > pathIdxEnd) {
            // Path is exhausted, only match if rest of pattern is * or **'s
            if (pattIdxStart > pattIdxEnd) {
                return (pattern.endsWith(PATH_SEPARATOR) == path.endsWith(PATH_SEPARATOR));
            }

            if (pattIdxStart == pattIdxEnd && pattDirs[pattIdxStart].equals("*") &&
                    path.endsWith(PATH_SEPARATOR)) {
                return true;
            }
            for (int i = pattIdxStart; i <= pattIdxEnd; i++) {
                if (!pattDirs[i].equals("**")) {
                    return false;
                }
            }
            return true;
        } else if (pattIdxStart > pattIdxEnd) {
            // String not exhausted, but pattern is. Failure.
            return false;
        }

        // up to last '**'
        while (pattIdxStart <= pattIdxEnd && pathIdxStart <= pathIdxEnd) {
            String patDir = pattDirs[pattIdxEnd];
            if (patDir.equals("**")) {
                break;
            }
            if (!matchStrings(patDir, pathDirs[pathIdxEnd])) {
                return false;
            }
            pattIdxEnd--;
            pathIdxEnd--;
        }
        if (pathIdxStart > pathIdxEnd) {
            // String is exhausted
            for (int i = pattIdxStart; i <= pattIdxEnd; i++) {
                if (!pattDirs[i].equals("**")) {
                    return false;
                }
            }
            return true;
        }

        while (pattIdxStart != pattIdxEnd && pathIdxStart <= pathIdxEnd) {
            int patIdxTmp = -1;
            for (int i = pattIdxStart + 1; i <= pattIdxEnd; i++) {
                if (pattDirs[i].equals("**")) {
                    patIdxTmp = i;
                    break;
                }
            }
            if (patIdxTmp == pattIdxStart + 1) {
                // '**/**' situation, so skip one
                pattIdxStart++;
                continue;
            }
            // Find the pattern between padIdxStart & padIdxTmp in str between
            // strIdxStart & strIdxEnd
            int patLength = (patIdxTmp - pattIdxStart - 1);
            int strLength = (pathIdxEnd - pathIdxStart + 1);
            int foundIdx = -1;

            strLoop:
            for (int i = 0; i <= strLength - patLength; i++) {
                for (int j = 0; j < patLength; j++) {
                    String subPat = pattDirs[pattIdxStart + j + 1];
                    String subStr = pathDirs[pathIdxStart + i + j];
                    if (!matchStrings(subPat, subStr)) {
                        continue strLoop;
                    }
                }
                foundIdx = pathIdxStart + i;
                break;
            }

            if (foundIdx == -1) {
                return false;
            }

            pattIdxStart = patIdxTmp;
            pathIdxStart = foundIdx + patLength;
        }

        for (int i = pattIdxStart; i <= pattIdxEnd; i++) {
            if (!pattDirs[i].equals("**")) {
                return false;
            }
        }

        return true;
    }

    /**
     * Tests whether or not a string matches against a pattern.
     * The pattern may contain two special characters:<br>
     * '*' means zero or more characters<br>
     * '?' means one and only one character
     *
     * @param pattern pattern to match against.
     *                Must not be <code>null</code>.
     * @param str     string which must be matched against the pattern.
     *                Must not be <code>null</code>.
     * @return <code>true</code> if the string matches against the
     * pattern, or <code>false</code> otherwise.
     */
    private boolean matchStrings(String pattern, String str) {
        char[] patArr = pattern.toCharArray();
        char[] strArr = str.toCharArray();
        int patIdxStart = 0;
        int patIdxEnd = patArr.length - 1;
        int strIdxStart = 0;
        int strIdxEnd = strArr.length - 1;
        char ch;

        boolean containsStar = false;
        for (char aPatArr : patArr) {
            if (aPatArr == '*') {
                containsStar = true;
                break;
            }
        }

        if (!containsStar) {
            // No '*'s, so we make a shortcut
            if (patIdxEnd != strIdxEnd) {
                return false; // Pattern and string do not have the same size
            }
            for (int i = 0; i <= patIdxEnd; i++) {
                ch = patArr[i];
                if (ch != '?') {
                    if (ch != strArr[i]) {
                        return false;// Character mismatch
                    }
                }
            }
            return true; // String matches against pattern
        }

        if (patIdxEnd == 0) {
            return true; // Pattern contains only '*', which matches anything
        }

        // Process characters before first star
        while ((ch = patArr[patIdxStart]) != '*' && strIdxStart <= strIdxEnd) {
            if (ch != '?') {
                if (ch != strArr[strIdxStart]) {
                    return false;// Character mismatch
                }
            }
            patIdxStart++;
            strIdxStart++;
        }
        if (strIdxStart > strIdxEnd) {
            // All characters in the string are used. Check if only '*'s are
            // left in the pattern. If so, we succeeded. Otherwise failure.
            for (int i = patIdxStart; i <= patIdxEnd; i++) {
                if (patArr[i] != '*') {
                    return false;
                }
            }
            return true;
        }

        // Process characters after last star
        while ((ch = patArr[patIdxEnd]) != '*' && strIdxStart <= strIdxEnd) {
            if (ch != '?') {
                if (ch != strArr[strIdxEnd]) {
                    return false;// Character mismatch
                }
            }
            patIdxEnd--;
            strIdxEnd--;
        }
        if (strIdxStart > strIdxEnd) {
            // All characters in the string are used. Check if only '*'s are
            // left in the pattern. If so, we succeeded. Otherwise failure.
            for (int i = patIdxStart; i <= patIdxEnd; i++) {
                if (patArr[i] != '*') {
                    return false;
                }
            }
            return true;
        }

        // process pattern between stars. padIdxStart and patIdxEnd point
        // always to a '*'.
        while (patIdxStart != patIdxEnd && strIdxStart <= strIdxEnd) {
            int patIdxTmp = -1;
            for (int i = patIdxStart + 1; i <= patIdxEnd; i++) {
                if (patArr[i] == '*') {
                    patIdxTmp = i;
                    break;
                }
            }
            if (patIdxTmp == patIdxStart + 1) {
                // Two stars next to each other, skip the first one.
                patIdxStart++;
                continue;
            }
            // Find the pattern between padIdxStart & padIdxTmp in str between
            // strIdxStart & strIdxEnd
            int patLength = (patIdxTmp - patIdxStart - 1);
            int strLength = (strIdxEnd - strIdxStart + 1);
            int foundIdx = -1;
            strLoop:
            for (int i = 0; i <= strLength - patLength; i++) {
                for (int j = 0; j < patLength; j++) {
                    ch = patArr[patIdxStart + j + 1];
                    if (ch != '?') {
                        if (ch != strArr[strIdxStart + i + j]) {
                            continue strLoop;
                        }
                    }
                }

                foundIdx = strIdxStart + i;
                break;
            }

            if (foundIdx == -1) {
                return false;
            }

            patIdxStart = patIdxTmp;
            strIdxStart = foundIdx + patLength;
        }

        // All characters in the string are used. Check if only '*'s are left
        // in the pattern. If so, we succeeded. Otherwise failure.
        for (int i = patIdxStart; i <= patIdxEnd; i++) {
            if (patArr[i] != '*') {
                return false;
            }
        }

        return true;
    }

}
