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
package be.atbash.ee.oauth2.sdk.assertions.jwt;


import be.atbash.ee.oauth2.sdk.BadJWTException;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;

import java.util.*;


/**
 * {@link JWTClaimsSetVerifier JWT claims verifier} implementation. This class
 * is thread-safe.
 *
 * <p>Performs the following checks:
 *
 * <ol>
 *     <li>If an expiration time (exp) claim is present, makes sure it is ahead
 *         of the current time, else the JWT claims set is rejected.
 *     <li>If a not-before-time (nbf) claim is present, makes sure it is
 *         before the current time, else the JWT claims set is rejected.
 * </ol>
 *
 * <p>This class may be extended to perform additional checks.
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-10-17
 */
public class DefaultJWTClaimsVerifier {


    /**
     * The default maximum acceptable clock skew, in seconds (60).
     */
    public static final int DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60;


    /**
     * The maximum acceptable clock skew, in seconds.
     */
    private int maxClockSkew = DEFAULT_MAX_CLOCK_SKEW_SECONDS;


    /**
     * The accepted audience values, {@code null} if not specified. A
     * {@code null} value present in the set allows JWTs with no audience.
     */
    private final Set<String> acceptedAudienceValues;


    /**
     * The JWT claims that must match exactly, empty set if none.
     */
    private final JWTClaimsSet exactMatchClaims;


    /**
     * The names of the JWT claims that must be present, empty set if none.
     */
    private final Set<String> requiredClaims;


    /**
     * The names of the JWT claims that must not be present, empty set if
     * none.
     */
    private final Set<String> prohibitedClaims;


    /**
     * Creates a new JWT claims verifier. No audience ("aud"), required and
     * prohibited claims are specified. Will check the expiration ("exp")
     * and not-before ("nbf") times if present.
     */
    public DefaultJWTClaimsVerifier() {
        this(null, null, null, null);
    }


    /**
     * Creates a new JWT claims verifier. Allows any audience ("aud")
     * unless an exact match is specified. Will check the expiration
     * ("exp") and not-before ("nbf") times if present.
     *
     * @param exactMatchClaims The JWT claims that must match exactly,
     *                         {@code null} if none.
     * @param requiredClaims   The names of the JWT claims that must be
     *                         present, empty set or {@code null} if none.
     */
    public DefaultJWTClaimsVerifier(final JWTClaimsSet exactMatchClaims,
                                    final Set<String> requiredClaims) {

        this(null, exactMatchClaims, requiredClaims, null);
    }


    /**
     * Creates new default JWT claims verifier.
     *
     * @param requiredAudience The required JWT audience, {@code null} if
     *                         not specified.
     * @param exactMatchClaims The JWT claims that must match exactly,
     *                         {@code null} if none.
     * @param requiredClaims   The names of the JWT claims that must be
     *                         present, empty set or {@code null} if none.
     */
    public DefaultJWTClaimsVerifier(final String requiredAudience,
                                    final JWTClaimsSet exactMatchClaims,
                                    final Set<String> requiredClaims) {

        this(requiredAudience != null ? Collections.singleton(requiredAudience) : null,
                exactMatchClaims,
                requiredClaims,
                null);
    }


    /**
     * Creates new default JWT claims verifier.
     *
     * @param acceptedAudience The accepted JWT audience values,
     *                         {@code null} if not specified. A
     *                         {@code null} value in the set allows JWTs
     *                         with no audience.
     * @param exactMatchClaims The JWT claims that must match exactly,
     *                         {@code null} if none.
     * @param requiredClaims   The names of the JWT claims that must be
     *                         present, empty set or {@code null} if none.
     * @param prohibitedClaims The names of the JWT claims that must not be
     *                         present, empty set or {@code null} if none.
     */
    public DefaultJWTClaimsVerifier(final Set<String> acceptedAudience,
                                    final JWTClaimsSet exactMatchClaims,
                                    final Set<String> requiredClaims,
                                    final Set<String> prohibitedClaims) {

        this.acceptedAudienceValues = acceptedAudience != null ? Collections.unmodifiableSet(acceptedAudience) : null;

        this.exactMatchClaims = exactMatchClaims != null ? exactMatchClaims : new JWTClaimsSet.Builder().build();

        Set<String> requiredClaimsCopy = new HashSet<>(this.exactMatchClaims.getClaims().keySet());
        if (acceptedAudienceValues != null && !acceptedAudienceValues.contains(null)) {
            // check if an explicit aud is required
            requiredClaimsCopy.add("aud");
        }
        if (requiredClaims != null) {
            requiredClaimsCopy.addAll(requiredClaims);
        }
        this.requiredClaims = Collections.unmodifiableSet(requiredClaimsCopy);

        this.prohibitedClaims = prohibitedClaims != null ? Collections.unmodifiableSet(prohibitedClaims) : Collections.<String>emptySet();
    }


    /**
     * Returns the accepted audience values.
     *
     * @return The accepted JWT audience values, {@code null} if not
     * specified. A {@code null} value in the set allows JWTs with
     * no audience.
     */
    public Set<String> getAcceptedAudienceValues() {
        return acceptedAudienceValues;
    }


    /**
     * Returns the JWT claims that must match exactly.
     *
     * @return The JWT claims that must match exactly, empty set if none.
     */
    public JWTClaimsSet getExactMatchClaims() {
        return exactMatchClaims;
    }


    /**
     * Returns the names of the JWT claims that must be present, including
     * the name of those that must match exactly.
     *
     * @return The names of the JWT claims that must be present, empty set
     * if none.
     */
    public Set<String> getRequiredClaims() {
        return requiredClaims;
    }


    /**
     * Returns the names of the JWT claims that must not be present.
     *
     * @return The names of the JWT claims that must not be present, empty
     * set if none.
     */
    public Set<String> getProhibitedClaims() {
        return prohibitedClaims;
    }


    public int getMaxClockSkew() {
        return maxClockSkew;
    }


    public void setMaxClockSkew(final int maxClockSkewSeconds) {
        maxClockSkew = maxClockSkewSeconds;
    }


    public void verify(final JWTClaimsSet claimsSet)
            throws BadJWTException {

        // Check audience
        if (acceptedAudienceValues != null) {
            List<String> audList = claimsSet.getAudience();
            if (audList != null && !audList.isEmpty()) {
                boolean audMatch = false;
                for (String aud : audList) {
                    if (acceptedAudienceValues.contains(aud)) {
                        audMatch = true;
                        break;
                    }
                }
                if (!audMatch) {
                    throw new BadJWTException("JWT audience rejected: " + audList);
                }
            } else if (!acceptedAudienceValues.contains(null)) {
                throw new BadJWTException("JWT missing required audience");
            }
        }

        // Check if all required claims are present
        if (!claimsSet.getClaims().keySet().containsAll(requiredClaims)) {
            Set<String> missingClaims = new HashSet<>(requiredClaims);
            missingClaims.removeAll(claimsSet.getClaims().keySet());
            throw new BadJWTException("JWT missing required claims: " + missingClaims);
        }

        // Check if prohibited claims are present
        Set<String> presentProhibitedClaims = new HashSet<>();
        for (String prohibited : prohibitedClaims) {
            if (claimsSet.getClaims().containsKey(prohibited)) {
                presentProhibitedClaims.add(prohibited);
            }
            if (!presentProhibitedClaims.isEmpty()) {
                throw new BadJWTException("JWT has prohibited claims: " + presentProhibitedClaims);
            }
        }

        // Check exact matches
        for (String exactMatch : exactMatchClaims.getClaims().keySet()) {
            Object value = claimsSet.getClaim(exactMatch);
            if (!value.equals(exactMatchClaims.getClaim(exactMatch))) {
                throw new BadJWTException("JWT \"" + exactMatch + "\" claim doesn't match expected value: " + value);
            }
        }

        // Check time window
        final Date now = new Date();

        final Date exp = claimsSet.getExpirationTime();
        if (exp != null) {

            if (!DateUtils.isAfter(exp, now, maxClockSkew)) {
                throw new BadJWTException("Expired JWT");
            }
        }

        final Date nbf = claimsSet.getNotBeforeTime();
        if (nbf != null) {

            if (!DateUtils.isBefore(nbf, now, maxClockSkew)) {
                throw new BadJWTException("JWT before use time");
            }
        }
    }
}
