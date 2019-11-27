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
package be.atbash.ee.oauth2.sdk.util;


import java.net.URI;


/**
 * Resource server URI utilities.
 */
public final class ResourceUtils {


    /**
     * Returns {@code true} if the specified resource URI is valid.
     *
     * @param resourceURI The resource URI. Must not be {@code null}.
     * @return {@code true} if the resource URI is valid, {@code false} if
     * the URI is not absolute or has a query or fragment.
     */
    public static boolean isValidResourceURI(URI resourceURI) {

        return
                resourceURI.getHost() != null
                        && resourceURI.getQuery() == null
                        && resourceURI.getFragment() == null;
    }


    /**
     * Prevents public instantiation.
     */
    private ResourceUtils() {
    }
}
