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
package be.atbash.ee.oauth2.sdk.util;


import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;


/**
 * X.509 certificate utilities.
 */
public final class X509CertificateUtils {


    /**
     * Checks if the issuer DN and the subject DN of the specified X.509
     * certificate match. The matched DNs are not normalised.
     *
     * @param cert The X.509 certificate. Must not be {@code null}.
     * @return {@code true} if the issuer DN and and subject DN match, else
     * {@code false}.
     */
    public static boolean hasMatchingIssuerAndSubject(X509Certificate cert) {

        Principal issuer = cert.getIssuerDN();
        Principal subject = cert.getSubjectDN();

        return issuer != null && subject != null && issuer.equals(subject);
    }


    /**
     * Checks if the specified X.509 certificate is self-issued, i.e. it
     * has a matching issuer and subject, and the public key can be used to
     * successfully validate the certificate's digital signature.
     *
     * @param cert The X.509 certificate. Must not be {@code null}.
     * @return {@code true} if the X.509 certificate is self-issued, else
     * {@code false}.
     */
    public static boolean isSelfIssued(X509Certificate cert) {

        return hasMatchingIssuerAndSubject(cert) && isSelfSigned(cert);
    }


    /**
     * Checks if the specified X.509 certificate is self-signed, i.e. the
     * public key can be used to successfully validate the certificate's
     * digital signature.
     *
     * @param cert The X.509 certificate. Must not be {@code null}.
     * @return {@code true} if the X.509 certificate is self-signed, else
     * {@code false}.
     */
    public static boolean isSelfSigned(X509Certificate cert) {

        PublicKey publicKey = cert.getPublicKey();

        return hasValidSignature(cert, publicKey);
    }


    /**
     * Validates the signature of a X.509 certificate with the specified
     * public key.
     *
     * @param cert   The X.509 certificate. Must not be {@code null}.
     * @param pubKey The public key to use for the validation. Must not be
     *               {@code null}.
     * @return {@code true} if the signature is valid, else {@code false}.
     */
    public static boolean hasValidSignature(X509Certificate cert,
                                            PublicKey pubKey) {

        try {
            cert.verify(pubKey);
        } catch (Exception e) {
            return false;
        }

        return true;
    }


    /**
     * Returns {@code true} if the public key of the X.509 certificate
     * matches the specified public key.
     *
     * @param cert   The X.509 certificate. Must not be {@code null}.
     * @param pubKey The public key to compare. Must not be {@code null}.
     * @return {@code true} if the two public keys match, else
     * {@code false}.
     */
    public static boolean publicKeyMatches(X509Certificate cert,
                                           PublicKey pubKey) {

        PublicKey certPubKey = cert.getPublicKey();

        return Arrays.equals(certPubKey.getEncoded(), pubKey.getEncoded());
    }


    /**
     * Prevents public instantiation.
     */
    private X509CertificateUtils() {
    }
}
