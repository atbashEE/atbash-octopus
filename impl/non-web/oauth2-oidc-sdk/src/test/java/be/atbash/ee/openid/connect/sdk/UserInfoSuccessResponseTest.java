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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.openid.connect.sdk.claims.UserInfo;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import org.junit.Test;

import javax.mail.internet.InternetAddress;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the UserInfo success response.
 */
public class UserInfoSuccessResponseTest {

    @Test
    public void testPlain()
            throws Exception {

        UserInfo claims = new UserInfo(new Subject("alice"));
        claims.setName("Alice Adams");
        claims.setEmail(new InternetAddress("alice@wonderland.net"));
        claims.setEmailVerified(true);

        UserInfoSuccessResponse response = new UserInfoSuccessResponse(claims);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getContentType().toString()).isEqualTo("application/json; charset=UTF-8");
        assertThat(response.getUserInfoJWT()).isNull();
        assertThat(response.getUserInfo()).isEqualTo(claims);
        HTTPResponse httpResponse = response.toHTTPResponse();

        response = UserInfoSuccessResponse.parse(httpResponse);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getContentType().toString()).isEqualTo("application/json; charset=UTF-8");
        assertThat(response.getUserInfoJWT()).isNull();

        claims = response.getUserInfo();

        assertThat(claims.getSubject().getValue()).isEqualTo("alice");
        assertThat(claims.getName()).isEqualTo("Alice Adams");
        assertThat(claims.getEmail().toString()).isEqualTo("alice@wonderland.net");
        assertThat(claims.getEmailVerified()).isTrue();
    }

    @Test
    public void testJWT()
            throws Exception {

        UserInfo claims = new UserInfo(new Subject("alice"));
        claims.setName("Alice Adams");
        claims.setEmail(new InternetAddress("alice@wonderland.net"));
        claims.setEmailVerified(true);

        JWTClaimsSet claimsSet = claims.toJWTClaimsSet();

        Secret secret = new Secret();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

        jwt.sign(new MACSigner(secret.getValueBytes()));

        UserInfoSuccessResponse response = new UserInfoSuccessResponse(jwt);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getUserInfoJWT()).isEqualTo(jwt);
        assertThat(response.getContentType().toString()).isEqualTo("application/jwt; charset=UTF-8");
        assertThat(response.getUserInfo()).isNull();

        HTTPResponse httpResponse = response.toHTTPResponse();

        response = UserInfoSuccessResponse.parse(httpResponse);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getContentType().toString()).isEqualTo("application/jwt; charset=UTF-8");
        assertThat(response.getUserInfo()).isNull();

        jwt = (SignedJWT) response.getUserInfoJWT();

        assertThat(jwt.getState().equals(JWSObject.State.SIGNED)).isTrue();

        claims = new UserInfo(response.getUserInfoJWT().getJWTClaimsSet().toJSONObject());

        assertThat(claims.getSubject().getValue()).isEqualTo("alice");
        assertThat(claims.getName()).isEqualTo("Alice Adams");
        assertThat(claims.getEmail().toString()).isEqualTo("alice@wonderland.net");
        assertThat(claims.getEmailVerified()).isTrue();
    }
}
