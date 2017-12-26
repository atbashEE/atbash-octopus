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
package be.atbash.ee.security.octopus.jwk;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.jwk.config.JwtSupportConfiguration;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.Scanner;

/**
 *
 */
@ApplicationScoped
public class JWKManager {

    private JWKSet jwkSet;

    @Inject
    private JwtSupportConfiguration JwtSupportConfiguration;

    @PostConstruct
    public void init() {
        jwkSet = readJWKSet();
    }

    private JWKSet readJWKSet() {
        JWKSet result;
        String jwkFile = JwtSupportConfiguration.getJWKFile();
        if (!StringUtils.hasText(jwkFile)) {
            throw new ConfigurationException("A value for the parameter jwk.file is required");
        }

        InputStream inputStream = JWKManager.class.getClassLoader().getResourceAsStream(jwkFile);
        try {
            if (inputStream == null) {
                inputStream = new FileInputStream(jwkFile);
            }
            String content = new Scanner(inputStream).useDelimiter("\\Z").next();
            result = JWKSet.parse(content);
        } catch (FileNotFoundException e) {
            throw new ConfigurationException(String.format("JWK File not found at %s", jwkFile));
        } catch (ParseException e) {
            throw new ConfigurationException(String.format("Parsing the JWK file failed with %s", e.getMessage()));
        }

        try {
            inputStream.close();
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }

        return result;
    }

    public boolean existsApiKey(String apiKey) {
        return jwkSet.getKeyByKeyId(apiKey) != null;
    }

    public JWK getJWKForApiKey(String apiKey) {
        return jwkSet.getKeyByKeyId(apiKey);
    }

    public JWK getJWKSigningKey() {
        boolean multiple = false;
        JWK result = null;
        for (JWK jwk : jwkSet.getKeys()) {
            if (jwk.isPrivate() && jwk.getKeyUse() == KeyUse.SIGNATURE) {
                if (result == null) {
                    result = jwk;
                } else {
                    multiple = true;
                }
            }
        }
        if (multiple) {
            throw new ConfigurationException("FIXME Multiple signing keys");
        }
        if (result == null) {
            throw new ConfigurationException("FIXME No signing key found");
        }
        return result;
    }

}
