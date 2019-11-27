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
package be.atbash.ee.openid.connect.sdk.claims;


import be.atbash.ee.oauth2.sdk.id.Identifier;

/**
 * Authentication Method Reference ({@code amr}). It identifies the method
 * used in authentication.
 *
 * <p>The AMR is represented by a string or an URI string.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>RFC 8176.
 *     <li>OpenID Connect Core 1.0, section 2.
 * </ul>
 */
public final class AMR extends Identifier {


    /**
     * Biometric authentication (RFC 4949) using facial recognition.
     */
    public static final AMR FACE = new AMR("face");


    /**
     * Biometric authentication (RFC 4949) using a fingerprint.
     */
    public static final AMR FPT = new AMR("fpt");


    /**
     * Use of geolocation information for authentication, such as that
     * provided by W3C REC-geolocation-API-20161108.
     */
    public static final AMR GEO = new AMR("geo");


    /**
     * Proof-of-Possession (PoP) of a hardware-secured key. See Appendix C
     * of RFC 4211 for a discussion on PoP.
     */
    public static final AMR HWK = new AMR("hwk");


    /**
     * Biometric authentication (RFC 4949) using an iris scan.
     */
    public static final AMR IRIS = new AMR("iris");


    /**
     * Retina scan biometric.
     */
    @Deprecated
    public static final AMR EYE = new AMR("eye");


    /**
     * Knowledge-based authentication (NIST.800-63-2, ISO29115).
     */
    public static final AMR KBA = new AMR("kba");


    /**
     * Multiple-channel authentication (MCA). The authentication involves
     * communication over more than one distinct communication channel. For
     * instance, a multiple-channel authentication might involve both
     * entering information into a workstation's browser and providing
     * information on a telephone call to a pre-registered number.
     */
    public static final AMR MCA = new AMR("mca");


    /**
     * Multiple-factor authentication (NIST.800-63-2, ISO29115). When this
     * is present, specific authentication methods used may also be
     * included.
     */
    public static final AMR MFA = new AMR("mfa");


    /**
     * One-time password (RFC 4949). One-time password specifications that
     * this authentication method applies to include RFC 4226 and RFC 6238.
     */
    public static final AMR OTP = new AMR("otp");


    /**
     * Personal Identification Number (PIN) (RFC 4949) or pattern (not
     * restricted to containing only numbers) that a user enters to unlock
     * a key on the device. This mechanism should have a way to deter an
     * attacker from obtaining the PIN by trying repeated guesses.
     */
    public static final AMR PIN = new AMR("pin");


    /**
     * Proof-of-possession (PoP) of a key. See Appendix C of RFC 4211 for a
     * discussion on PoP.
     */
    @Deprecated
    public static final AMR POP = new AMR("pop");


    /**
     * Password-based authentication (RFC 4949).
     */
    public static final AMR PWD = new AMR("pwd");


    /**
     * Risk-based authentication (Williamson, G., "Enhanced Authentication
     * In Online Banking", Journal of Economic Crime Management 4.2: 18-19,
     * 2006).
     */
    public static final AMR RBA = new AMR("rba");


    /**
     * Smart card (RFC 4949).
     */
    public static final AMR SC = new AMR("sc");


    /**
     * Confirmation using SMS text message to the user at a registered
     * number.
     */
    public static final AMR SMS = new AMR("sms");


    /**
     * Proof-of-Possession (PoP) of a software-secured key. See Appendix C
     * of RFC 4211 for a discussion on PoP.
     */
    public static final AMR SWK = new AMR("swk");


    /**
     * Confirmation by telephone call to the user at a registered number.
     * This authentication technique is sometimes also referred to as
     * "call back" (RFC 4949).
     */
    public static final AMR TEL = new AMR("tel");


    /**
     * User presence test. Evidence that the end user is present and
     * interacting with the device.  This is sometimes also referred to as
     * "test of user presence" (W3C WD-webauthn-20170216).
     */
    public static final AMR USER = new AMR("user");


    /**
     * Biometric authentication (RFC 4949) using a voiceprint.
     */
    public static final AMR VBM = new AMR("vbm");


    /**
     * Windows integrated authentication (Microsoft, "Integrated Windows
     * Authentication with Negotiate", September 2011).
     */
    public static final AMR WIA = new AMR("wia");


    /**
     * Creates a new Authentication Method Reference (AMR) with the
     * specified value.
     *
     * @param value The AMR value. Must not be {@code null}.
     */
    public AMR(String value) {

        super(value);
    }


    @Override
    public boolean equals(Object object) {

        return object instanceof AMR &&
                this.toString().equals(object.toString());
    }
}
