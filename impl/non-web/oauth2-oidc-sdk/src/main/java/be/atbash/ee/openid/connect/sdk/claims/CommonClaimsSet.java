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
package be.atbash.ee.openid.connect.sdk.claims;


import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.Subject;

import jakarta.json.JsonObject;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


/**
 * Common claims set.
 */
abstract class CommonClaimsSet extends ClaimsSet {


    /**
     * The issuer claim name.
     */
    public static final String ISS_CLAIM_NAME = "iss";


    /**
     * The subject claim name.
     */
    public static final String SUB_CLAIM_NAME = "sub";


    /**
     * The audience claim name.
     */
    public static final String AUD_CLAIM_NAME = "aud";


    /**
     * The issue time claim name.
     */
    public static final String IAT_CLAIM_NAME = "iat";


    /**
     * The session identifier claim name.
     */
    public static final String SID_CLAIM_NAME = "sid";


    /**
     * Creates a new empty common claims set.
     */
    protected CommonClaimsSet() {

        super();
    }


    /**
     * Creates a new common claims set from the specified JSON object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     */
    protected CommonClaimsSet(JsonObject jsonObject) {

        super(jsonObject);
    }


    /**
     * Gets the issuer. Corresponds to the {@code iss} claim.
     *
     * @return The issuer, {@code null} if not specified.
     */
    public Issuer getIssuer() {

        String val = getStringClaim(ISS_CLAIM_NAME);
        return val != null ? new Issuer(val) : null;
    }


    /**
     * Gets the subject. Corresponds to the {@code sub} claim.
     *
     * @return The subject.
     */
    public Subject getSubject() {

        String val = getStringClaim(SUB_CLAIM_NAME);
        return val != null ? new Subject(val) : null;
    }


    /**
     * Gets the audience. Corresponds to the {@code aud} claim.
     *
     * @return The audience, {@code null} if not specified.
     */
    public List<Audience> getAudience() {

        if (getClaim(AUD_CLAIM_NAME) instanceof String) {
            // Special case - aud is a string
            return new Audience(getStringClaim(AUD_CLAIM_NAME)).toSingleAudienceList();
        }

        // General case - JSON string array
        List<String> rawList = getStringListClaim(AUD_CLAIM_NAME);

        if (rawList == null) {
            return null;
        }

        List<Audience> audList = new ArrayList<>(rawList.size());

        for (String s : rawList) {
            audList.add(new Audience(s));
        }

        return audList;
    }


    /**
     * Gets the issue time. Corresponds to the {@code iss} claim.
     *
     * @return The issue time, {@code null} if not specified.
     */
    public Date getIssueTime() {

        return getDateClaim(IAT_CLAIM_NAME);
    }


    /**
     * Gets the session ID. Corresponds to the {@code sid} claim.
     *
     * @return The session ID, {@code null} if not specified.
     */
    public SessionID getSessionID() {

        String val = getStringClaim(SID_CLAIM_NAME);

        return val != null ? new SessionID(val) : null;
    }


    /**
     * Sets the session ID. Corresponds to the {@code sid} claim.
     *
     * @param sid The session ID, {@code null} if not specified.
     */
    public void setSessionID(SessionID sid) {

        setClaim(SID_CLAIM_NAME, sid != null ? sid.getValue() : null);
    }
}
