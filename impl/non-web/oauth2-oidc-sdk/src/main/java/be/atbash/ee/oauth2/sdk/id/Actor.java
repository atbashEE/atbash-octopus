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


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.io.Serializable;


/**
 * Authorised actor in impersonation and delegation cases.
 */
// FIXME Will this be used in Octopus?
public final class Actor implements Serializable, Comparable<Actor> {


    /**
     * The actor subject.
     */
    private final Subject subject;


    /**
     * Optional issuer for the actor subject.
     */
    private final Issuer issuer;


    /**
     * Optional parent for the actor.
     */
    private final Actor parent;


    /**
     * Creates a new actor.
     *
     * @param subject The subject. Must not be {@code null}.
     */
    public Actor(final Subject subject) {
        this(subject, null, null);
    }


    /**
     * Creates a new actor.
     *
     * @param subject The subject. Must not be {@code null}.
     * @param issuer  Optional issuer for the subject, {@code null} if
     *                not specified.
     * @param parent  Optional parent for the actor, {@code null} if none.
     */
    public Actor(final Subject subject, final Issuer issuer, final Actor parent) {
        if (subject == null) {
            throw new IllegalArgumentException("The subject must not be null");
        }
        this.subject = subject;
        this.issuer = issuer;
        this.parent = parent;
    }


    /**
     * Returns the subject.
     *
     * @return The subject.
     */
    public Subject getSubject() {
        return subject;
    }


    /**
     * Returns the optional issuer for the subject.
     *
     * @return The issuer, {@code null} if not specified.
     */
    public Issuer getIssuer() {
        return issuer;
    }


    /**
     * Returns the optional parent for this actor.
     *
     * @return The optional parent for the actor, {@code null} if none.
     */
    public Actor getParent() {
        return parent;
    }


    /**
     * Returns a JSON object representation of this actor.
     *
     * <p>Simple example:
     *
     * <pre>
     * {
     *   "sub" : "admin@example.com"
     * }
     * </pre>
     *
     * <p>With nesting:
     *
     * <pre>
     * {
     *   "sub" : "consumer.example.com-web-application",
     *   "iss" : "https://issuer.example.net",
     *   "act" : { "sub":"admin@example.com" }
     * }
     * </pre>
     *
     * @return The JSON object.
     */
    public JsonObject toJSONObject() {

        JsonObjectBuilder result = Json.createObjectBuilder();
        result.add("sub", subject.getValue());

        if (issuer != null) {
            result.add("iss", issuer.getValue());
        }

        if (parent != null) {
            result.add("act", parent.toJSONObject());
        }

        return result.build();
    }


    @Override
    public int compareTo(final Actor other) {

        return toJSONString().compareTo(other.toJSONString());
    }


    public String toJSONString() {
        return toJSONObject().toString();
    }


    @Override
    public String toString() {
        return toJSONString();
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Actor)) {
            return false;
        }

        Actor actor = (Actor) o;

        if (!subject.equals(actor.subject)) {
            return false;
        }
        if (issuer != null ? !issuer.equals(actor.issuer) : actor.issuer != null) {
            return false;
        }
        return parent != null ? parent.equals(actor.parent) : actor.parent == null;

    }


    @Override
    public int hashCode() {
        int result = subject.hashCode();
        result = 31 * result + (issuer != null ? issuer.hashCode() : 0);
        result = 31 * result + (parent != null ? parent.hashCode() : 0);
        return result;
    }


    /**
     * Parses an actor from the specified JSON object representation.
     *
     * <p>Simple example:
     *
     * <pre>
     * {
     *   "sub" : "admin@example.com"
     * }
     * </pre>
     *
     * <p>With nesting:
     *
     * <pre>
     * {
     *   "sub" : "consumer.example.com-web-application",
     *   "iss" : "https://issuer.example.net",
     *   "act" : { "sub":"admin@example.com" }
     * }
     * </pre>
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @return The actor.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static Actor parse(final JsonObject jsonObject)
            throws OAuth2JSONParseException {

        Subject sub = new Subject(jsonObject.getString("sub"));

        Issuer iss = null;

        if (jsonObject.containsKey("iss")) {
            iss = new Issuer(jsonObject.getString("iss"));
        }

        Actor parent = parseTopLevel(jsonObject);

        return new Actor(sub, iss, parent);
    }


    /**
     * Parses an actor from the specified top-level JSON object contains
     * an optional actor JSON representation.
     *
     * <p>Simple example:
     *
     * <pre>
     * {
     *   "aud" : "https://consumer.example.com",
     *   "iss" : "https://issuer.example.com",
     *   "exp" : 1443904177,
     *   "nbf" : 1443904077,
     *   "sub" : "user@example.com",
     *   "act" : { "sub" : "admin@example.com" }
     * }
     * </pre>
     *
     * <p>With nesting:
     *
     * <pre>
     * {
     *   "aud" : "https://backend.example.com",
     *   "iss" : "https://issuer.example.com",
     *   "exp" : 1443904100,
     *   "nbf" : 1443904000,
     *   "sub" : "user@example.com",
     *   "act" : { "sub" : "consumer.example.com-web-application",
     *             "iss" : "https://issuer.example.net",
     *             "act" : { "sub":"admin@example.com" } }
     * }
     * </pre>
     *
     * @param jsonObject The top-level JSON object to parse. Must not be
     *                   {@code null}.
     * @return The actor, {@code null} if not specified.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static Actor parseTopLevel(final JsonObject jsonObject)
            throws OAuth2JSONParseException {

        JsonObject actSpec = jsonObject.getJsonObject("act");

        if (actSpec == null) {
            return null;
        }

        return parse(actSpec);
    }
}
