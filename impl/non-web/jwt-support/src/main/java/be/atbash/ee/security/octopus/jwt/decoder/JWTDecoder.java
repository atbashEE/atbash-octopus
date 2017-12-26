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
package be.atbash.ee.security.octopus.jwt.decoder;

import be.atbash.ee.security.octopus.jwt.InvalidJWTException;
import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.keys.KeySelector;
import be.atbash.json.JSONValue;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jwt.SignedJWT;

import javax.enterprise.context.ApplicationScoped;
import java.security.Key;
import java.text.ParseException;

/**
 *
 */
@ApplicationScoped
public class JWTDecoder {

    private DefaultJWSVerifierFactory jwsVerifierFactory = new DefaultJWSVerifierFactory();

    public <T> T decode(String data, Class<T> classType) {
        return decode(data, classType, null, null).getData();
    }

    public <T> JWTData<T> decode(String data, Class<T> classType, KeySelector keySelector, JWTVerifier verifier) {
        JWTEncoding encoding = determineEncoding(data);
        if (encoding == null) {
            throw new IllegalArgumentException("Unable to determine the encoding of the data");
        }

        JWTData<T> result;
        try {
            switch (encoding) {

                case NONE:
                    result = readJSONString(data, classType);
                    break;
                case JWS:
                    if (keySelector == null) {
                        throw new AtbashIllegalActionException("(OCT-DEV-101) keySelector required for decoding a JWT encoded value");
                    }
                    result = readSignedJWT(data, keySelector, classType, verifier);
                    break;
                case JWE:
                    result = null;
                    break;
                default:
                    throw new IllegalArgumentException(String.format("JWTEncoding not supported %s", encoding));
            }
        } catch (ParseException e) {
            throw new InvalidJWTException("Invalid JWT structure");
        } catch (JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }
        return result;
    }

    private <T> JWTData<T> readSignedJWT(String data, KeySelector keySelector, Class<T> classType, JWTVerifier verifier) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(data);

        String keyID = signedJWT.getHeader().getKeyID();
        Key key = keySelector.selectSecretKey(keyID);
        if (key == null) {
            throw new InvalidJWTException(String.format("No key found for %s", keyID));
        }

        JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(signedJWT.getHeader(), key);

        if (!signedJWT.verify(jwsVerifier)) {
            throw new InvalidJWTException("JWT Signature verification failed");
        }

        if (verifier != null) {
            if (!verifier.verify(signedJWT.getHeader(), signedJWT.getJWTClaimsSet())) {
                throw new InvalidJWTException("JWT verification failed");
            }
        }
        MetaJWTData metaJWTData = new MetaJWTData(keyID, signedJWT.getHeader().getCustomParams());

        return readJSONString(signedJWT.getPayload().toString(), classType, metaJWTData);
    }

    private <T> JWTData<T> readJSONString(String data, Class<T> classType) {
        return readJSONString(data, classType, new MetaJWTData());
    }

    private <T> JWTData<T> readJSONString(String data, Class<T> classType, MetaJWTData metaJWTData) {
        return new JWTData<>(JSONValue.parse(data, classType), metaJWTData);
    }

    private JWTEncoding determineEncoding(String data) {
        JWTEncoding result = null;
        if (data.startsWith("{")) {
            result = JWTEncoding.NONE;
        }

        if (data.startsWith("ey")) {
            int occurrences = StringUtils.countOccurrences(data, '.');
            if (occurrences == 2) {
                result = JWTEncoding.JWS;
            }
            if (occurrences == 4) {
                result = JWTEncoding.JWS;
            }
        }
        return result;
    }
}
