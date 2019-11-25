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
package be.atbash.ee.openid.connect.sdk.op;


import be.atbash.ee.oauth2.sdk.GeneralException;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.openid.connect.sdk.SubjectType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import java.io.IOException;
import java.net.URI;
import java.util.Collections;

import static net.jadler.Jadler.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class OIDCProviderMetadataResolveTest {


    @Before
    public void setUp() {
        initJadler();
    }


    @After
    public void tearDown() {
        closeJadler();
    }


    @Test
    public void testResolveOK()
            throws Exception {

        Issuer issuer = new Issuer("http://localhost:" + port());

        OIDCProviderMetadata metadata = new OIDCProviderMetadata(
                issuer,
                Collections.singletonList(SubjectType.PAIRWISE),
                URI.create("http://localhost:" + port() + "/jwks.json"));
        metadata.applyDefaults();

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/.well-known/openid-configuration")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(metadata.toJSONObject().build().toString());

        OIDCProviderMetadata result = OIDCProviderMetadata.resolve(issuer);

        assertThat(result.getIssuer()).isEqualTo(issuer);
    }


    @Test
    public void testResolveWithPathOK()
            throws Exception {

        Issuer issuer = new Issuer("http://localhost:" + port() + "/tenant-1");

        OIDCProviderMetadata metadata = new OIDCProviderMetadata(
                issuer,
                Collections.singletonList(SubjectType.PAIRWISE),
                URI.create("http://localhost:" + port() + "/jwks.json"));
        metadata.applyDefaults();

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/tenant-1/.well-known/openid-configuration")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(metadata.toJSONObject().build().toString());

        OIDCProviderMetadata result = OIDCProviderMetadata.resolve(issuer);

        assertThat(result.getIssuer()).isEqualTo(issuer);
    }


    @Test
    public void testResolveWithPathTrailingSlashOK()
            throws Exception {

        Issuer issuer = new Issuer("http://localhost:" + port() + "/tenant-1/");

        OIDCProviderMetadata metadata = new OIDCProviderMetadata(
                issuer,
                Collections.singletonList(SubjectType.PAIRWISE),
                URI.create("http://localhost:" + port() + "/jwks.json"));
        metadata.applyDefaults();

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/tenant-1/.well-known/openid-configuration")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(metadata.toJSONObject().build().toString());

        OIDCProviderMetadata result = OIDCProviderMetadata.resolve(issuer);

        assertThat(result.getIssuer()).isEqualTo(issuer);
    }


    @Test
    public void testResolveInvalidMetadata()
            throws Exception {

        Issuer issuer = new Issuer("http://localhost:" + port());

        JsonObjectBuilder jsonObjectbuilder = Json.createObjectBuilder();
        jsonObjectbuilder.add("issuer", issuer.getValue());

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/.well-known/openid-configuration")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(jsonObjectbuilder.build().toString());

        try {
            OIDCProviderMetadata.resolve(issuer);
            fail();
        } catch (GeneralException e) {
            assertThat(e.getMessage()).isEqualTo("Missing JSON object member with key \"subject_types_supported\"");
        }
    }


    @Test
    public void testResolveNotFound404()
            throws Exception {

        Issuer issuer = new Issuer("http://localhost:" + port());

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/.well-known/openid-configuration")
                .respond()
                .withStatus(404)
                .withContentType("text/plain")
                .withBody("Not Found");

        try {
            OIDCProviderMetadata.resolve(issuer);
            fail();
        } catch (IOException e) {
            assertThat(e.getMessage()).isEqualTo("Couldn't download OpenID Provider metadata from http://localhost:" + port() + "/.well-known/openid-configuration: Status code 404");
        }
    }


    @Test
    public void testIssuerMismatch()
            throws Exception {

        Issuer issuer = new Issuer("http://localhost:" + port());

        OIDCProviderMetadata metadata = new OIDCProviderMetadata(
                new Issuer("http://localhost/abcdef"),
                Collections.singletonList(SubjectType.PAIRWISE),
                URI.create("http://localhost:" + port() + "/jwks.json"));
        metadata.applyDefaults();

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/.well-known/openid-configuration")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(metadata.toJSONObject().build().toString());

        try {
            OIDCProviderMetadata.resolve(issuer);
            fail("Didn't raise issuer mismatch exception");
        } catch (GeneralException e) {
            assertThat(e.getMessage()).isEqualTo("The returned issuer doesn't match the expected: http://localhost/abcdef");
        }
    }
}

