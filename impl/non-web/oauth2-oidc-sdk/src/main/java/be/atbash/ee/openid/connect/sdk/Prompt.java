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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.util.StringUtils;

import java.util.*;


/**
 * Prompts for end-user re-authentication and consent.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.1.2.1.
 * </ul>
 */
public class Prompt extends LinkedHashSet<Prompt.Type> {


    /**
     * Enumeration of the prompt types.
     */
    public enum Type {


        /**
         * The authorisation server must not display any authentication
         * or consent UI pages. An error is returned if the end user is
         * not already authenticated or the client does not have
         * pre-configured consent for the requested {@code scope}. This
         * can be used as a method to check for existing authentication
         * and / or consent.
         */
        NONE,


        /**
         * The authorisation server must prompt the end-user for
         * re-authentication.
         */
        LOGIN,


        /**
         * The authorisation server must prompt the end-user for
         * consent before returning information to the client.
         */
        CONSENT,


        /**
         * The authorisation server must prompt the end-user to select
         * a user account. This allows a user who has multiple accounts
         * at the authorisation server to select amongst the multiple
         * accounts that they may have current sessions for.
         */
        SELECT_ACCOUNT;


        /**
         * Returns the string identifier of this prompt type.
         *
         * @return The string identifier.
         */
        @Override
        public String toString() {

            return super.toString().toLowerCase();
        }


        /**
         * Parses a prompt type.
         *
         * @param data The string to parse.
         * @return The prompt type.
         * @throws OAuth2JSONParseException If the parsed string is {@code null}
         *                                  or doesn't match a prompt type.
         */
        public static Type parse(String data)
                throws OAuth2JSONParseException {

            if (StringUtils.isEmpty(data)) {
                throw new OAuth2JSONParseException("Null or empty prompt type string");
            }

            switch (data) {
                case "none":
                    return NONE;
                case "login":
                    return LOGIN;
                case "consent":
                    return CONSENT;
                case "select_account":
                    return SELECT_ACCOUNT;
                default:
                    throw new OAuth2JSONParseException("Unknown prompt type: " + data);
            }
        }
    }


    /**
     * Creates a new empty prompt.
     */
    public Prompt() {

        // Nothing to do
    }


    /**
     * Creates a new prompt with the specified types.
     *
     * @param type The prompt types.
     */
    public Prompt(Type... type) {

        addAll(Arrays.asList(type));
    }


    /**
     * Creates a new prompt with the specified type values.
     *
     * @param values The prompt type values.
     * @throws java.lang.IllegalArgumentException If the type value is
     *                                            invalid.
     */
    public Prompt(String... values) {

        for (String v : values) {

            try {
                add(Type.parse(v));

            } catch (OAuth2JSONParseException e) {

                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }
    }


    /**
     * Checks if the prompt is valid. This is done by examining the prompt
     * for a conflicting {@link Type#NONE} value.
     *
     * @return {@code true} if this prompt if valid, else {@code false}.
     */
    public boolean isValid() {

        return !(size() > 1 && contains(Type.NONE));
    }


    /**
     * Returns the string list representation of this prompt.
     *
     * @return The string list representation.
     */
    public List<String> toStringList() {

        List<String> list = new ArrayList<>(this.size());

        for (Type t : this) {
            list.add(t.toString());
        }

        return list;
    }


    /**
     * Returns the string representation of this prompt. The values are
     * delimited by space.
     *
     * <p>Example:
     *
     * <pre>
     * login consent
     * </pre>
     *
     * @return The string representation.
     */
    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();

        Iterator<Type> it = super.iterator();

        while (it.hasNext()) {

            sb.append(it.next().toString());

            if (it.hasNext()) {
                sb.append(" ");
            }
        }

        return sb.toString();
    }


    /**
     * Parses a prompt from the specified string list.
     *
     * @param collection The string list to parse, with one or more
     *                   non-conflicting prompt types. May be {@code null}.
     * @return The prompt, {@code null} if the parsed string list was
     * {@code null} or empty.
     * @throws OAuth2JSONParseException If the string list couldn't be parsed to a
     *                                  valid prompt.
     */
    public static Prompt parse(Collection<String> collection)
            throws OAuth2JSONParseException {

        if (collection == null) {
            return null;
        }

        Prompt prompt = new Prompt();

        for (String s : collection) {
            prompt.add(Prompt.Type.parse(s));
        }

        if (!prompt.isValid()) {
            throw new OAuth2JSONParseException("Invalid prompt: " + collection);
        }

        return prompt;
    }


    /**
     * Parses a prompt from the specified string.
     *
     * @param s The string to parse, with one or more non-conflicting space
     *          delimited prompt types. May be {@code null}.
     * @return The prompt, {@code null} if the parsed string was
     * {@code null} or empty.
     * @throws OAuth2JSONParseException If the string couldn't be parsed to a valid
     *                                  prompt.
     */
    public static Prompt parse(String s)
            throws OAuth2JSONParseException {

        if (StringUtils.isEmpty(s)) {
            return null;
        }

        Prompt prompt = new Prompt();

        StringTokenizer st = new StringTokenizer(s, " ");

        while (st.hasMoreTokens()) {
            prompt.add(Prompt.Type.parse(st.nextToken()));
        }

        if (!prompt.isValid()) {
            throw new OAuth2JSONParseException("Invalid prompt: " + s);
        }

        return prompt;
    }
}
