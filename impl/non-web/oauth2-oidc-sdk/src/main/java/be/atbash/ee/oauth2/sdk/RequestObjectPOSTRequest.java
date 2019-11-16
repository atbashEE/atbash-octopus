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
package be.atbash.ee.oauth2.sdk;


import be.atbash.ee.oauth2.sdk.auth.PKITLSClientAuthentication;
import be.atbash.ee.oauth2.sdk.auth.SelfSignedTLSClientAuthentication;
import be.atbash.ee.oauth2.sdk.auth.TLSClientAuthentication;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;
import be.atbash.ee.security.octopus.nimbus.jwt.PlainJWT;

import javax.json.JsonObject;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;


/**
 * Request object POST request.
 *
 * <p>Example request object POST request:
 *
 * <pre>
 * POST /requests HTTP/1.1
 * Host: c2id.com
 * Content-Type: application/jws
 * Content-Length: 1288
 *
 * eyJhbGciOiJSUzI1NiIsImtpZCI6ImsyYmRjIn0.ew0KICJpc3MiOiA
 * (... abbreviated for brevity ...)
 * zCYIb_NMXvtTIVc1jpspnTSD7xMbpL-2QgwUsAlMGzw
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial-grade API - Part 2: Read and Write API Security Profile,
 *         section 7.
 *     <li>The OAuth 2.0 Authorization Framework: JWT Secured Authorization
 *         Request (JAR) (draft-ietf-oauth-jwsreq-17).
 * </ul>
 */
@Deprecated
// FIXME Remove Deprecated stuff
public final class RequestObjectPOSTRequest extends AbstractOptionallyAuthenticatedRequest {


    /**
     * The request object as JWT, {@code null} for a
     * {@link #requestJSONObject plain JSON object}.
     */
    private final JWT requestObject;


    /**
     * The request parameters as plain JSON object, {@code null} for
     * {@link #requestObject JWT}.
     */
    private final JsonObject requestJSONObject;


    /**
     * Creates a new request object POST request.
     *
     * @param uri           The URI of the request object endpoint. May be
     *                      {@code null} if the {@link #toHTTPRequest}
     *                      method will not be used.
     * @param requestObject The request object. Must not be {@code null}.
     */
    public RequestObjectPOSTRequest(final URI uri,
                                    final JWT requestObject) {

        super(uri, null);

        if (requestObject == null) {
            throw new IllegalArgumentException("The request object must not be null");
        }

        if (requestObject instanceof PlainJWT) {
            throw new IllegalArgumentException("The request object must not be an unsecured JWT (alg=none)");
        }

        this.requestObject = requestObject;

        requestJSONObject = null;
    }


    /**
     * Creates a new request object POST request where the parameters are
     * submitted as plain JSON object, and the client authenticates by
     * means of mutual TLS. TLS also ensures the integrity and
     * confidentiality of the request parameters. This method is not
     * standard.
     *
     * @param uri               The URI of the request object endpoint. May
     *                          be {@code null} if the
     *                          {@link #toHTTPRequest} method will not be
     *                          used.
     * @param tlsClientAuth     The mutual TLS client authentication. Must
     *                          not be {@code null}.
     * @param requestJSONObject The request parameters as plain JSON
     *                          object. Must not be {@code null}.
     */
    public RequestObjectPOSTRequest(final URI uri,
                                    final TLSClientAuthentication tlsClientAuth,
                                    final JsonObject requestJSONObject) {

        super(uri, tlsClientAuth);

        if (tlsClientAuth == null) {
            throw new IllegalArgumentException("The mutual TLS client authentication must not be null");
        }

        if (requestJSONObject == null) {
            throw new IllegalArgumentException("The request JSON object must not be null");
        }

        this.requestJSONObject = requestJSONObject;

        requestObject = null;
    }


    /**
     * Returns the request object as JWT.
     *
     * @return The request object as JWT, {@code null} if the request
     * parameters are specified as {@link #getRequestJSONObject()
     * plain JSON object} instead.
     */
    public JWT getRequestObject() {

        return requestObject;
    }


    /**
     * Returns the request object as plain JSON object.
     *
     * @return The request parameters as plain JSON object, {@code null}
     * if the request object is specified as a
     * {@link #getRequestObject() JWT}.
     */
    public JsonObject getRequestJSONObject() {

        return requestJSONObject;
    }


    /**
     * Returns the mutual TLS client authentication.
     *
     * @return The mutual TLS client authentication.
     */
    public TLSClientAuthentication getTLSClientAuthentication() {

        return (TLSClientAuthentication) getClientAuthentication();
    }


    @Override
    public HTTPRequest toHTTPRequest() {

        if (getEndpointURI() == null) {
            throw new SerializeException("The endpoint URI is not specified");
        }

        URL url;
        try {
            url = getEndpointURI().toURL();
        } catch (MalformedURLException e) {
            throw new SerializeException(e.getMessage(), e);
        }

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, url);

        if (getRequestObject() != null) {
            httpRequest.setContentType(CommonContentTypes.APPLICATION_JWT);
            httpRequest.setQuery(getRequestObject().serialize());
        } else if (getRequestJSONObject() != null) {
            httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);
            httpRequest.setQuery(getRequestJSONObject().toString());
            getTLSClientAuthentication().applyTo(httpRequest);
        }

        return httpRequest;
    }


    /**
     * Parses a request object POST request from the specified HTTP
     * request.
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     * @return The request object POST request.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to a
     *                                  request object POST request.
     */
    public static RequestObjectPOSTRequest parse(final HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        // Only HTTP POST accepted
        httpRequest.ensureMethod(HTTPRequest.Method.POST);

        if (httpRequest.getContentType() == null) {
            throw new OAuth2JSONParseException("Missing Content-Type");
        }

        if (
                CommonContentTypes.APPLICATION_JOSE.match(httpRequest.getContentType()) ||
                        CommonContentTypes.APPLICATION_JWT.match(httpRequest.getContentType())) {

            // Signed or signed and encrypted request object

            JWT requestObject;
            try {
                requestObject = JWTParser.parse(httpRequest.getQuery());
            } catch (java.text.ParseException e) {
                throw new OAuth2JSONParseException("Invalid request object JWT: " + e.getMessage());
            }

            if (requestObject instanceof PlainJWT) {
                throw new OAuth2JSONParseException("The request object is an unsecured JWT (alg=none)");
            }

            return new RequestObjectPOSTRequest(httpRequest.getURI(), requestObject);

        } else if (CommonContentTypes.APPLICATION_JSON.match(httpRequest.getContentType())) {

            JsonObject jsonObject = httpRequest.getQueryAsJSONObject();

            if (jsonObject.get("client_id") == null) {
                throw new OAuth2JSONParseException("Missing client_id in JSON object");
            }

            ClientID clientID = new ClientID(jsonObject.getString("client_id"));

            // TODO
            TLSClientAuthentication tlsClientAuth;
            if (httpRequest.getClientX509Certificate() != null && httpRequest.getClientX509CertificateSubjectDN() != null &&
                    httpRequest.getClientX509CertificateSubjectDN().equals(httpRequest.getClientX509CertificateRootDN())) {
                tlsClientAuth = new SelfSignedTLSClientAuthentication(clientID, httpRequest.getClientX509Certificate());
            } else if (httpRequest.getClientX509Certificate() != null) {
                tlsClientAuth = new PKITLSClientAuthentication(clientID, httpRequest.getClientX509Certificate());
            } else {
                throw new OAuth2JSONParseException("Missing mutual TLS client authentication");
            }

            return new RequestObjectPOSTRequest(httpRequest.getURI(), tlsClientAuth, jsonObject);

        } else {

            throw new OAuth2JSONParseException("Unexpected Content-Type: " + httpRequest.getContentType());
        }
    }
}
