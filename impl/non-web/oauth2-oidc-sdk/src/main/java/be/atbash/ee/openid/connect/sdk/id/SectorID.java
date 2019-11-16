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
package be.atbash.ee.openid.connect.sdk.id;


import be.atbash.ee.oauth2.sdk.id.Identifier;

import java.net.URI;


/**
 * Sector identifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 8.1.
 * </ul>
 */
public final class SectorID extends Identifier {


    /**
     * Ensures the specified URI has a {@code https} scheme.
     *
     * @param sectorURI The URI. Must have a {@code https} scheme and not
     *                  be {@code null}.
     */
    public static void ensureHTTPScheme(final URI sectorURI) {

        if (!"https".equalsIgnoreCase(sectorURI.getScheme())) {
            throw new IllegalArgumentException("The URI must have a https scheme");
        }
    }


    /**
     * Ensures the specified URI contains a host component.
     *
     * @param sectorURI The URI. Must contain a host component and not be
     *                  {@code null}.
     * @return The host component.
     */
    public static String ensureHostComponent(final URI sectorURI) {

        String host = sectorURI.getHost();

        if (host == null) {
            throw new IllegalArgumentException("The URI must contain a host component");
        }

        return host;
    }


    /**
     * Creates a new sector identifier for the specified host.
     *
     * @param host The host. Must not be empty or {@code null}.
     */
    public SectorID(final String host) {
        super(host);
    }


    /**
     * Creates a new sector identifier for the specified URI.
     *
     * @param sectorURI The sector URI. Must contain a host component and
     *                  must not be {@code null}.
     */
    public SectorID(final URI sectorURI) {
        super(ensureHostComponent(sectorURI));
    }
}
