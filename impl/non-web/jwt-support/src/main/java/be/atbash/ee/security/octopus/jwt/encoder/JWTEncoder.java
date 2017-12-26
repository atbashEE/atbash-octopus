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
package be.atbash.ee.security.octopus.jwt.encoder;

import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersEncryption;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersSigning;
import be.atbash.json.JSONValue;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.*;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class JWTEncoder {

    @Inject
    private JWTSignerFactory signerFactory;

    public String encode(Object data, JWTParameters parameters) {
        checkDependencies();

        String result;

        try {
            switch (parameters.getEncoding()) {
                case NONE:
                    result = createJSONString(data);
                    break;
                case JWS:
                    result = createSignedJWT(data, (JWTParametersSigning) parameters);
                    break;
                case JWE:
                    result = createEncryptedJWE(data, (JWTParametersEncryption) parameters);
                    break;
                default:
                    throw new IllegalArgumentException(String.format("JWTEncoding not supported %s", parameters.getEncoding()));
            }
        } catch (JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }
        return result;

    }

    private String createEncryptedJWE(Object data, JWTParametersEncryption parameters) throws JOSEException {
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512)
                        .keyID(parameters.getKeyID())
                        .customParams(parameters.getHeaderValues())
                        .contentType("JWT") // required to signal nested JWT
                        .build(),
                new Payload(createSignedJWT(data, parameters.getParametersSigning())));

        // Perform encryption
        //jweObject.encrypt(new RSAEncrypter(parameters.getJWK()));  // FIXME

        // Serialise to JWE compact form
        return jweObject.serialize();
    }

    private String createSignedJWT(Object data, JWTParametersSigning parameters) throws JOSEException {
        JWSObject jwsObject = createJWTObject(data, parameters);
        return jwsObject.serialize();
    }

    private JWSObject createJWTObject(Object data, JWTParametersSigning parameters) throws JOSEException {
        String payload = createJSONString(data);

        JWSObject jwsObject;

        JWSHeader header = new JWSHeader.Builder(signerFactory.defineJWSAlgorithm(parameters))
                .type(JOSEObjectType.JWT)
                .keyID(parameters.getKeyID())
                .customParams(parameters.getHeaderValues())
                .build();

        jwsObject = new JWSObject(header, new Payload(payload));

        // Apply the Signing protection
        JWSSigner signer = signerFactory.createSigner(parameters);

        jwsObject.sign(signer);

        return jwsObject;
    }

    private String createJSONString(Object data) {
        return JSONValue.toJSONString(data);
    }

    private void checkDependencies() {
        // We have CDI injected dependencies, but in a Java SE environment it is possible that they are empty.
        if (signerFactory == null) {
            signerFactory = new JWTSignerFactory();
        }
    }

}
