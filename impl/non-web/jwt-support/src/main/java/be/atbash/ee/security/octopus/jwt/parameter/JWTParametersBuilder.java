/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.jwt.parameter;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.keys.SecretKeyType;
import be.atbash.util.Reviewed;
import be.atbash.util.exception.AtbashIllegalActionException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@Reviewed
public final class JWTParametersBuilder {

    private Logger logger = LoggerFactory.getLogger(JWTParametersBuilder.class);

    private JWTEncoding encoding;

    private Map<String, Object> headerValues;
    private JWK secretKeySigning;
    private SecretKeyType secretKeyType;

    private JWK secretKeyEncryption;
    private JWTParametersSigning parametersSigning;

    private JWTParametersBuilder(JWTEncoding encoding) {
        this.encoding = encoding;
    }

    public JWTParametersBuilder withHeader(String key, String value) {
        if (encoding == JWTEncoding.NONE) {
            logger.warn("Header values are not supported with JWTEncoding.NONE");
        }
        if (headerValues == null) {
            headerValues = new HashMap<>();

        }
        headerValues.put(key, value);
        return this;
    }

    public JWTParametersBuilder withSecretKeyForSigning(JWK key) {
        if (encoding == JWTEncoding.NONE) {
            logger.warn("SecretKey value is not supported with JWTEncoding.NONE");
        }
        secretKeySigning = key;
        determineSecretKeyType();
        return this;
    }

    private void determineSecretKeyType() {
        if (KeyType.OCT.equals(secretKeySigning.getKeyType())) {
            secretKeyType = SecretKeyType.HMAC;
        }
        if (KeyType.RSA.equals(secretKeySigning.getKeyType())) {
            secretKeyType = SecretKeyType.RSA;
        }
        if (KeyType.EC.equals(secretKeySigning.getKeyType())) {
            secretKeyType = SecretKeyType.EC;
        }

    }

    public JWTParametersBuilder withSecretKeyForEncryption(JWK key) {
        if (encoding != JWTEncoding.JWE) {
            logger.warn("SecretKey value for encryption only needed for JWTEncoding.JWE");
        }
        secretKeyEncryption = key;
        return this;
    }

    public JWTParametersBuilder withSigningParameters(JWTParametersSigning parametersSigning) {

        this.parametersSigning = parametersSigning;
        return this;
    }

    public JWTParameters build() {
        JWTParameters result;

        validateParameters();

        switch (encoding) {

            case NONE:
                result = new JWTParametersNone();
                break;
            case JWS:
                result = new JWTParametersSigning(headerValues, secretKeyType, secretKeySigning);
                break;
            case JWE:
                result = new JWTParametersEncryption(parametersSigning, headerValues, secretKeyEncryption);
                break;
            default:
                throw new IllegalArgumentException(String.format("Unsupported value for JWTEncoding : %s", encoding));
        }
        return result;
    }

    private void validateParameters() {
        switch (encoding) {

            case NONE:
                break;
            case JWS:
                validateJWSParameters();
                break;
            case JWE:
                validateJWEParameters();
                break;
            default:
                throw new IllegalArgumentException(String.format("Unsupported value for JWTEncoding : %s", encoding));
        }

    }

    private void validateJWEParameters() {
        if (secretKeyEncryption == null) {
            throw new AtbashIllegalActionException("JWE encoding requires a JWK secret for the encryption");
        }

    }

    private void validateJWSParameters() {

        if (secretKeySigning == null) {
            throw new AtbashIllegalActionException("JWS encoding requires a JWK secret for the signing");
        }

    }

    public static JWTParametersBuilder newBuilderFor(JWTEncoding encoding) {
        return new JWTParametersBuilder(encoding);
    }
}
