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


import java.net.URI;


/**
 * The base abstract class for requests.
 */
public abstract class AbstractRequest implements Request {


    /**
     * The request endpoint.
     */
    private final URI uri;


    /**
     * Creates a new base abstract request.
     *
     * @param uri The URI of the endpoint (HTTP or HTTPS) for which the
     *            request is intended, {@code null} if not specified (if,
     *            for example, the {@link #toHTTPRequest()} method will not
     *            be used).
     */
    public AbstractRequest(URI uri) {

        this.uri = uri;
    }


    @Override
    public URI getEndpointURI() {

        return uri;
    }
}
