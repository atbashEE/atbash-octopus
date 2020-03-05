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
package be.atbash.ee.openid.connect.sdk.rp;


import be.atbash.ee.oauth2.sdk.GrantType;
import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.client.*;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.openid.connect.sdk.SubjectType;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACVerifier;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import org.junit.jupiter.api.Test;

import javax.mail.internet.InternetAddress;
import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the OIDC client registration class.
 */
public class OIDCClientRegistrationRequestTest {

    @Test
    public void testRoundtrip() throws Exception {

        URI uri = new URI("https://server.example.com/connect/register");

        OIDCClientMetadata metadata = new OIDCClientMetadata();

        Set<URI> redirectURIs = new HashSet<>();
        redirectURIs.add(new URI("https://client.example.org/callback"));
        metadata.setRedirectionURIs(redirectURIs);

        metadata.setApplicationType(ApplicationType.NATIVE);

        metadata.setJWKSetURI(new URI("https://client.example.org/my_public_keys.jwks"));

        OIDCClientRegistrationRequest request = new OIDCClientRegistrationRequest(uri, metadata, null);

        assertThat(request.getEndpointURI()).isEqualTo(uri);

        assertThat(request.getAccessToken()).isNull();

        metadata = request.getOIDCClientMetadata();

        redirectURIs = metadata.getRedirectionURIs();
        assertThat(redirectURIs.contains(new URI("https://client.example.org/callback"))).isTrue();
        assertThat(redirectURIs).hasSize(1);

        assertThat(metadata.getApplicationType()).isEqualTo(ApplicationType.NATIVE);

        assertThat(metadata.getJWKSetURI()).isEqualTo(new URI("https://client.example.org/my_public_keys.jwks"));

        HTTPRequest httpRequest = request.toHTTPRequest();

        assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
        assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_JSON.toString());


        request = OIDCClientRegistrationRequest.parse(httpRequest);

        assertThat(request.getEndpointURI()).isEqualTo(uri);

        assertThat(request.getAccessToken()).isNull();

        metadata = request.getOIDCClientMetadata();

        redirectURIs = metadata.getRedirectionURIs();
        assertThat(redirectURIs.contains(new URI("https://client.example.org/callback"))).isTrue();
        assertThat(redirectURIs).hasSize(1);

        assertThat(metadata.getApplicationType()).isEqualTo(ApplicationType.NATIVE);

        assertThat(metadata.getJWKSetURI()).isEqualTo(new URI("https://client.example.org/my_public_keys.jwks"));
    }

    @Test
    public void testParse() throws Exception {

        URI uri = new URI("https://server.example.com/connect/register");

        String json = "{"
                + "   \"application_type\": \"web\","
                + "   \"redirect_uris\":[\"https://client.example.org/callback\",\"https://client.example.org/callback2\"],"
                + "   \"client_name\": \"My Example\","
                + "   \"logo_uri\": \"https://client.example.org/logo.png\","
                + "   \"subject_type\": \"pairwise\","
                + "   \"sector_identifier_uri\":\"https://other.example.net/file_of_redirect_uris.json\","
                + "   \"token_endpoint_auth_method\": \"client_secret_basic\","
                + "   \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\","
                + "   \"userinfo_encrypted_response_alg\": \"RSA-OAEP-256\","
                + "   \"userinfo_encrypted_response_enc\": \"A128CBC-HS256\","
                + "   \"contacts\": [\"ve7jtb@example.org\", \"mary@example.org\"],"
                + "   \"request_uris\":[\"https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA\"]"
                + "  }";


        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, uri.toURL());
        httpRequest.setAuthorization("Bearer eyJhbGciOiJSUzI1NiJ9.eyJ");
        httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpRequest.setQuery(json);

        OIDCClientRegistrationRequest req = OIDCClientRegistrationRequest.parse(httpRequest);

        assertThat(req.getEndpointURI()).isEqualTo(uri);

        OIDCClientMetadata metadata = req.getOIDCClientMetadata();

        assertThat(metadata.getApplicationType()).isEqualTo(ApplicationType.WEB);

        Set<URI> redirectURIs = metadata.getRedirectionURIs();
        assertThat(redirectURIs.contains(new URI("https://client.example.org/callback"))).isTrue();
        assertThat(redirectURIs.contains(new URI("https://client.example.org/callback2"))).isTrue();
        assertThat(redirectURIs).hasSize(2);

        assertThat(metadata.getName()).isEqualTo("My Example");

        assertThat(metadata.getLogoURI()).isEqualTo(new URI("https://client.example.org/logo.png"));

        assertThat(metadata.getSubjectType()).isEqualTo(SubjectType.PAIRWISE);
        assertThat(metadata.getSectorIDURI()).isEqualTo(new URI("https://other.example.net/file_of_redirect_uris.json"));

        assertThat(metadata.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        assertThat(metadata.getJWKSetURI()).isEqualTo(new URI("https://client.example.org/my_public_keys.jwks"));

        assertThat(metadata.getUserInfoJWEAlg()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(metadata.getUserInfoJWEEnc()).isEqualTo(EncryptionMethod.A128CBC_HS256);

        List<InternetAddress> contacts = metadata.getContacts();
        assertThat(contacts.contains(new InternetAddress("ve7jtb@example.org"))).isTrue();
        assertThat(contacts.contains(new InternetAddress("mary@example.org"))).isTrue();
        assertThat(contacts).hasSize(2);

        Set<URI> requestObjectURIs = metadata.getRequestObjectURIs();
        assertThat(requestObjectURIs.contains(new URI("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"))).isTrue();
    }

    @Test
    public void testSoftwareStatement()
            throws Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://c2id.com")
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        jwt.sign(new MACSigner("01234567890123456789012345678901"));

        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setRedirectionURI(new URI("https://client.com/in"));
        metadata.setName("Test App");

        OIDCClientRegistrationRequest request = new OIDCClientRegistrationRequest(new URI("https://c2id.com/reg"), metadata, jwt, null);

        assertThat(request.getClientMetadata()).isEqualTo(metadata);
        assertThat(request.getSoftwareStatement()).isEqualTo(jwt);
        assertThat(request.getAccessToken()).isNull();

        HTTPRequest httpRequest = request.toHTTPRequest();

        request = OIDCClientRegistrationRequest.parse(httpRequest);

        assertThat(request.getClientMetadata().getRedirectionURIs().iterator().next().toString()).isEqualTo("https://client.com/in");
        assertThat(request.getClientMetadata().getName()).isEqualTo("Test App");
        assertThat(request.getSoftwareStatement().getParsedString()).isEqualTo(jwt.serialize());
        assertThat(request.getSoftwareStatement().verify(new MACVerifier("01234567890123456789012345678901"))).isTrue();
    }

    @Test
    public void testRejectUnsignedSoftwareStatement()
            throws Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://c2id.com")
                .build();

        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setRedirectionURI(new URI("https://client.com/in"));
        metadata.setName("Test App");

        try {
            new OIDCClientRegistrationRequest(
                    new URI("https://c2id.com/reg"),
                    metadata,
                    new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet),
                    null);

        } catch (IllegalArgumentException e) {

            // ok
            assertThat(e.getMessage()).isEqualTo("The software statement JWT must be signed");
        }

    }

    @Test
    public void testRejectSoftwareStatementWithoutIssuer()
            throws Exception {

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build());
        jwt.sign(new MACSigner("01234567890123456789012345678901"));

        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setRedirectionURI(new URI("https://client.com/in"));
        metadata.setName("Test App");

        try {
            new OIDCClientRegistrationRequest(
                    new URI("https://c2id.com/reg"),
                    metadata,
                    jwt,
                    null);

        } catch (IllegalArgumentException e) {

            // ok
            assertThat(e.getMessage()).isEqualTo("The software statement JWT must contain an 'iss' claim");
        }
    }

    @Test
    public void _testExampleRegisterForCodeGrant()
            throws Exception {

        // The client registration endpoint
        URI clientsEndpoint = new URI("https://demo.c2id.com/c2id/clients");

        // Master API token for the clients endpoint
        BearerAccessToken masterToken = new BearerAccessToken("ztucZS1ZyFKgh0tUEruUtiSTXhnexmd6");

        // We want to register a client for the code grant
        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
        clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
        clientMetadata.setName("My Client App");

        OIDCClientRegistrationRequest regRequest = new OIDCClientRegistrationRequest(
                clientsEndpoint,
                clientMetadata,
                masterToken
        );

        HTTPResponse httpResponse = regRequest.toHTTPRequest().send();

        ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

        if (!regResponse.indicatesSuccess()) {
            // We have an error
            ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse) regResponse;
            System.err.println(errorResponse.getErrorObject());
            return;
        }

        // Successful registration
        OIDCClientInformationResponse successResponse = (OIDCClientInformationResponse) regResponse;

        OIDCClientInformation clientInfo = successResponse.getOIDCClientInformation();

        // The client credentials - store them:

        //FIXME Make a proper test
        // The client_id
        //System.out.println("Client ID: " + clientInfo.getID());

        // The client_secret
        //System.out.println("Client secret: " + clientInfo.getSecret().getValue());

        // The client's registration resource
        //System.out.println("Client registration URI: " + clientInfo.getRegistrationURI());

        // The token for accessing the client's registration (for update, etc)
        //System.out.println("Client reg access token: " + clientInfo.getRegistrationAccessToken());

        // Print the remaining client metadata
        //System.out.println("Client metadata: " + clientInfo.getMetadata().toJSONObject());


        // Query
        ClientReadRequest readRequest = new ClientReadRequest(
                clientInfo.getRegistrationURI(),
                clientInfo.getRegistrationAccessToken()
        );

        httpResponse = readRequest.toHTTPRequest().send();

        regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

        if (!regResponse.indicatesSuccess()) {
            // We have an error
            ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse) regResponse;
            System.err.println(errorResponse.getErrorObject());
            return;
        }

        // Success
        successResponse = (OIDCClientInformationResponse) regResponse;



        // Update client name
        clientMetadata = clientInfo.getOIDCMetadata();
        clientMetadata.setName("My app has a new name");

        // Send request
        ClientUpdateRequest updateRequest = new ClientUpdateRequest(
                clientInfo.getRegistrationURI(),
                clientInfo.getID(),
                clientInfo.getRegistrationAccessToken(),
                clientMetadata,
                clientInfo.getSecret()
        );

        httpResponse = updateRequest.toHTTPRequest().send();

        regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

        if (!regResponse.indicatesSuccess()) {
            // We have an error
            ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse) regResponse;
            System.err.println(errorResponse.getErrorObject());
            return;
        }

        // Success
        successResponse = (OIDCClientInformationResponse) regResponse;

        // Ensure the client name has been updated
        clientInfo = successResponse.getOIDCClientInformation();


        // Request deletion
        ClientDeleteRequest deleteRequest = new ClientDeleteRequest(
                clientInfo.getRegistrationURI(),
                clientInfo.getRegistrationAccessToken()
        );

        httpResponse = deleteRequest.toHTTPRequest().send();

        regResponse = ClientRegistrationResponse.parse(httpResponse);

        if (!regResponse.indicatesSuccess()) {
            // We have an error
            ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse) regResponse;
            System.err.println(errorResponse.getErrorObject());
            return;
        }

        // Success: nothing returned
    }
}