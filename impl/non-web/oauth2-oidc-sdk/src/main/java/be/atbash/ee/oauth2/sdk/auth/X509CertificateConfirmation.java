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
package be.atbash.ee.oauth2.sdk.auth;


import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.X509CertUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.AbstractMap;
import java.util.Map;


/**
 * X.509 certificate SHA-256 confirmation.
 */
public final class X509CertificateConfirmation {


    /**
     * The X.509 certificate SHA-256 thumbprint.
     */
    private final Base64URLValue x5tS256;


    /**
     * Creates a new X.509 certificate SHA-256 confirmation.
     *
     * @param x5tS256 The X.509 certificate SHA-256 thumbprint.
     */
    public X509CertificateConfirmation(final Base64URLValue x5tS256) {

        if (x5tS256 == null) {
            throw new IllegalArgumentException("The X.509 certificate thumbprint must not be null");
        }

        this.x5tS256 = x5tS256;
    }


    /**
     * Returns the X.509 certificate SHA-256 thumbprint.
     *
     * @return The X.509 certificate SHA-256 thumbprint.
     */
    public Base64URLValue getValue() {

        return x5tS256;
    }


    /**
     * Returns this X.509 certificate SHA-256 confirmation as a JSON
     * object.
     *
     * <p>Example:
     *
     * <pre>
     * {
     *   "cnf" : { "x5t#S256" : "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" }
     * }
     * </pre>
     *
     * @return The JSON object.
     */
    public JsonObject toJSONObject() {

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();

        Map.Entry<String, JsonObject> cnfClaim = toJWTClaim();
        jsonObject.add(cnfClaim.getKey(), cnfClaim.getValue());
        return jsonObject.build();
    }


    /**
     * Returns this X.509 certificate SHA-256 confirmation as a JWT claim.
     *
     * <p>Example:
     *
     * <pre>
     * "cnf" : { "x5t#S256" : "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" }
     * </pre>
     *
     * @return The JWT claim name / value.
     */
    public Map.Entry<String, JsonObject> toJWTClaim() {

        JsonObjectBuilder cnf = Json.createObjectBuilder();

        cnf.add("x5t#S256", x5tS256.toString());

        return new AbstractMap.SimpleImmutableEntry<>(
                "cnf",
                cnf.build()
        );
    }


    /**
     * Applies this X.509 certificate SHA-256 confirmation to the specified
     * JWT claims set.
     *
     * @param jwtClaimsSet The JWT claims set.
     * @return The modified JWT claims set.
     */
    public JWTClaimsSet applyTo(final JWTClaimsSet jwtClaimsSet) {

        Map.Entry<String, JsonObject> cnfClaim = toJWTClaim();

        return new JWTClaimsSet.Builder(jwtClaimsSet)
                .claim(cnfClaim.getKey(), cnfClaim.getValue())
                .build();
    }


    @Override
    public String toString() {
        return toJSONObject().toString();
    }


    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof X509CertificateConfirmation)) {
            return false;
        }
        X509CertificateConfirmation that = (X509CertificateConfirmation) o;
        return x5tS256 != null ? x5tS256.equals(that.x5tS256) : that.x5tS256 == null;
    }


    @Override
    public int hashCode() {
        return x5tS256 != null ? x5tS256.hashCode() : 0;
    }


    /**
     * Parses a X.509 certificate confirmation from the specified JWT
     * claims set.
     *
     * @param jwtClaimsSet The JWT claims set.
     * @return The X.509 certificate confirmation, {@code null} if not
     * found.
     */
    public static X509CertificateConfirmation parse(final JWTClaimsSet jwtClaimsSet) {

        JsonObject cnf;
        try {
            cnf = jwtClaimsSet.getJSONObjectClaim("cnf");
        } catch (ParseException e) {
            return null;
        }

        return parseFromConfirmationJSONObject(cnf);
    }


    /**
     * Parses a X.509 certificate confirmation from the specified JSON
     * object representation of a JWT claims set.
     *
     * @param jsonObject The JSON object.
     * @return The X.509 certificate confirmation, {@code null} if not
     * found.
     */
    public static X509CertificateConfirmation parse(final JsonObject jsonObject) {

        if (!jsonObject.containsKey("cnf")) {
            return null;
        }

        return parseFromConfirmationJSONObject(jsonObject.getJsonObject("cnf"));
    }


    /**
     * Parses a X.509 certificate confirmation from the specified
     * confirmation ("cnf") JSON object.
     *
     * @param cnf The confirmation JSON object, {@code null} if none.
     * @return The X.509 certificate confirmation, {@code null} if not
     * found.
     */
    public static X509CertificateConfirmation parseFromConfirmationJSONObject(final JsonObject cnf) {

        if (cnf == null) {
            return null;
        }

        String x5tString = cnf.getString("x5t#S256", null);

        if (x5tString == null) {
            return null;
        }

        return new X509CertificateConfirmation(new Base64URLValue(x5tString));

    }


    /**
     * Creates a confirmation of the specified X.509 certificate.
     *
     * @param x509Cert The X.509 certificate.
     * @return The X.509 certificate confirmation.
     */
    public static X509CertificateConfirmation of(final X509Certificate x509Cert) {

        return new X509CertificateConfirmation(X509CertUtils.computeSHA256Thumbprint(x509Cert));
    }
}
