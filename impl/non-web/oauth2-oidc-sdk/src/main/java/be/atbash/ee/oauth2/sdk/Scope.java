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
package be.atbash.ee.oauth2.sdk;


import be.atbash.ee.oauth2.sdk.id.Identifier;

import java.util.*;


/**
 * Authorisation scope.
 *
 * <p>Example scope from OpenID Connect indicating access to the user's email
 * and profile details:
 *
 * <pre>
 * Scope scope = new Scope();
 * scope.add(OIDCScopeValue.OPENID);
 * scope.add(OIDCScopeValue.EMAIL);
 * scope.add(OIDCScopeValue.PROFILE);
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 3.3.
 * </ul>
 */
public class Scope extends LinkedHashSet<Scope.Value> {


    /**
     * Authorisation scope value.
     */
    public static class Value extends Identifier {


        /**
         * Enumeration of the scope value requirements for
         * application-specific authorisation requests.
         */
        public enum Requirement {


            /**
             * The value must be present in the {@link Scope}
             * parameter.
             */
            REQUIRED,


            /**
             * The value may be optionally included in the
             * {@link Scope} parameter.
             */
            OPTIONAL
        }


        /**
         * Optional requirement.
         */
        private final Value.Requirement requirement;


        /**
         * Creates a new scope value. The requirement is not specified.
         *
         * @param value The scope value. Must not be {@code null} or
         *              empty string.
         */
        public Value(final String value) {

            this(value, null);
        }

        /**
         * Creates a new scope value with an optional requirement.
         *
         * @param value       The scope value. Must not be {@code null}
         *                    or empty string.
         * @param requirement The requirement, {@code null} if not
         *                    specified.
         */
        public Value(final String value, final Requirement requirement) {

            super(value);

            this.requirement = requirement;
        }


        /**
         * Gets the requirement of this scope value.
         *
         * @return The requirement, {@code null} if not specified.
         */
        public Requirement getRequirement() {

            return requirement;
        }


        @Override
        public boolean equals(final Object object) {

            return object instanceof Value &&
                    this.toString().equals(object.toString());
        }
    }


    /**
     * Creates a new empty authorisation scope.
     */
    public Scope() {
        // Nothing to do
    }


    /**
     * Creates a new scope from the specified scope.
     *
     * @param scope The scope. May be {@code null}.
     */
    public Scope(final Scope scope) {

        if (scope == null) {
            return;
        }

        addAll(scope);
    }


    /**
     * Creates a new authorisation scope with the specified string values.
     *
     * @param values The string values.
     */
    public Scope(final String... values) {

        for (String v : values) {
            add(new Value(v));
        }
    }


    /**
     * Creates a new authorisation scope with the specified values.
     *
     * @param values The values.
     */
    public Scope(final Value... values) {

        addAll(Arrays.asList(values));
    }


    /**
     * Adds the specified string value to this scope.
     *
     * @param value The string value. Must not be {@code null}.
     * @return {@code true} if this scope did not already contain the
     * specified value.
     */
    public boolean add(final String value) {

        return add(new Value(value));
    }


    /**
     * Checks if this scope contains the specified string value.
     *
     * @param value The string value. Must not be {@code null}.
     * @return {@code true} if the value is contained, else {@code false}.
     */
    public boolean contains(final String value) {

        return contains(new Value(value));
    }


    /**
     * Returns the string representation of this scope. The scope values
     * will be serialised in the order they were added.
     *
     * @return The string representation.
     */
    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();

        for (Scope.Value v : this) {

            if (sb.length() > 0) {
                sb.append(' ');
            }

            sb.append(v.toString());
        }

        return sb.toString();
    }


    /**
     * Returns the string list representation of this scope. The scope
     * values will be serialised in the order they were added.
     *
     * @return The string list representation.
     */
    public List<String> toStringList() {

        List<String> list = new ArrayList<>(this.size());

        for (Scope.Value v : this) {
            list.add(v.getValue());
        }

        return list;
    }


    /**
     * Parses a scope from the specified string collection representation.
     *
     * @param collection The string collection, {@code null} if not
     *                   specified.
     * @return The scope, {@code null} if not specified.
     */
    public static Scope parse(final Collection<String> collection) {

        if (collection == null) {
            return null;
        }

        Scope scope = new Scope();

        for (String v : collection) {
            scope.add(new Scope.Value(v));
        }

        return scope;
    }


    /**
     * Parses a scope from the specified string representation.
     *
     * @param s The scope string, {@code null} if not specified.
     * @return The scope, {@code null} if not specified.
     */
    public static Scope parse(final String s) {

        if (s == null) {
            return null;
        }

        Scope scope = new Scope();

        if (s.trim().isEmpty()) {
            return scope;
        }

        // OAuth specifies space as delimiter, also support comma (old draft)
        StringTokenizer st = new StringTokenizer(s, " ,");

        while (st.hasMoreTokens()) {
            scope.add(new Scope.Value(st.nextToken()));
        }

        return scope;
    }
}
