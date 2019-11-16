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


import be.atbash.ee.oauth2.sdk.id.Identifier;
import be.atbash.util.StringUtils;

/**
 * User code.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Device Authorization Grant (draft-ietf-oauth-device-flow-15)
 * </ul>
 */
public final class UserCode extends Identifier {


    public static final String LETTER_CHAR_SET = "BCDFGHJKLMNPQRSTVWXZ";


    public static final String DIGIT_CHAR_SET = "0123456789";


    /**
     * The character set used by the identifier. The identifier can only
     * contain characters from this set.
     */
    private final String charset;


    /**
     * Creates a new user code with the specified value.
     *
     * @param value   The code value. Must not be {@code null} or empty
     *                string.
     * @param charset The character set used by the identifier. The
     *                identifier can only contain characters from this set.
     *                If {@code null}, all characters are allowed.
     */
    public UserCode(final String value, final String charset) {

        super(value);

        this.charset = charset;
    }


    /**
     * Creates a new user code with the specified value and the
     * {@code LETTER_CHAR_SET}.
     *
     * @param value The code value. Must not be {@code null} or empty
     *              string.
     */
    public UserCode(final String value) {

        this(value, LETTER_CHAR_SET);
    }


    /**
     * Creates a new user code with a randomly generated value with 8
     * characters from {@code LETTER_CHAR_SET}, in the form
     * {@code WDJB-MJHT}.
     */
    public UserCode() {

        this(LETTER_CHAR_SET, 8);
    }


    /**
     * Creates a new user code with a randomly generated value from the
     * specified charset and length. A dash is added every 4 characters.
     */
    public UserCode(final String charset, final int length) {

        this(generateValue(charset, length), charset);
    }


    /**
     * Creates a new user code with a randomly generated value from the
     * specified charset and length. A dash is added every 4 characters.
     *
     * @param charset The character set used by the identifier. The
     *                identifier can only contain characters from this set.
     *                Must not be {@code null} or empty string.
     * @param length  The length of the value to generate.
     */
    private static String generateValue(final String charset, final int length) {

        if (StringUtils.isEmpty(charset)) {
            throw new IllegalArgumentException("The charset must not be null or empty string");
        }

        StringBuilder value = new StringBuilder();
        for (int index = 0; index < length; index++) {
            if (index > 0 && index % 4 == 0) {
                value.append('-');
            }
            value.append(charset.charAt(secureRandom.nextInt(charset.length())));
        }
        return value.toString();
    }


    /**
     * Returns the character set used by this {@code UserCode}.
     *
     * @return The character set, or {@code null} if unspecified.
     */
    public String getCharset() {

        return charset;
    }


    /**
     * Returns the value with all invalid characters removed.
     *
     * @return The value with all invalid characters removed.
     */
    public String getStrippedValue() {

        return stripIllegalChars(getValue(), getCharset());
    }


    @Override
    public int compareTo(final Identifier other) {

        // fallback to default compare for other identifiers
        if (!(other instanceof UserCode)) {
            return super.compareTo(other);
        }

        return getStrippedValue().compareTo(((UserCode) other).getStrippedValue());
    }


    @Override
    public int hashCode() {

        return getStrippedValue() != null ? getStrippedValue().hashCode() : 0;
    }


    @Override
    public boolean equals(final Object object) {

        return object instanceof UserCode
                && this.getStrippedValue().equals(((UserCode) object).getStrippedValue());
    }


    /**
     * Removes all characters from {@code value} that are not in
     * {@code charset}.
     *
     * @param value   The code value.
     * @param charset The allowed characters in {@code value}. If
     *                {@code null} all characters are retained.
     * @return The {@code value} with all invalid characters removed.
     */
    public static String stripIllegalChars(final String value, final String charset) {

        if (charset == null) {
            return value.toUpperCase();
        }

        StringBuilder newValue = new StringBuilder();
        for (char curChar : value.toUpperCase().toCharArray()) {
            if (charset.indexOf(curChar) >= 0) {
                newValue.append(curChar);
            }
        }
        return newValue.toString();
    }
}
