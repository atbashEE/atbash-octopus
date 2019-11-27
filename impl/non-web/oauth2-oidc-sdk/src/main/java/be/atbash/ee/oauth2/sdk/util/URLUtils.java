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


import be.atbash.util.StringUtils;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.*;


/**
 * URL operations.
 */
public final class URLUtils {


    /**
     * The default UTF-8 character set.
     */
    public static final String CHARSET = "utf-8";


    /**
     * Gets the base part (protocol, host, port and path) of the specified
     * URL.
     *
     * @param url The URL. May be {@code null}.
     * @return The base part of the URL, {@code null} if the original URL
     * is {@code null} or doesn't specify a protocol.
     */
    public static URL getBaseURL(URL url) {

        if (url == null) {
            return null;
        }

        try {
            return new URL(url.getProtocol(), url.getHost(), url.getPort(), url.getPath());

        } catch (MalformedURLException e) {

            return null;
        }
    }


    /**
     * Serialises the specified map of parameters into a URL query string.
     * The parameter keys and values are
     * {@code application/x-www-form-urlencoded} encoded.
     *
     * <p>Note that the '?' character preceding the query string in GET
     * requests is not included in the returned string.
     *
     * <p>Example query string:
     *
     * <pre>
     * response_type=code
     * &amp;client_id=s6BhdRkqt3
     * &amp;state=xyz
     * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
     * </pre>
     *
     * <p>The opposite method is {@link #parseParameters}.
     *
     * @param params A map of the URL query parameters. May be empty or
     *               {@code null}.
     * @return The serialised URL query string, empty if no parameters.
     */
    public static String serializeParameters(Map<String, List<String>> params) {

        if (params == null || params.isEmpty()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        for (Map.Entry<String, List<String>> entry : params.entrySet()) {

            if (entry.getKey() == null || entry.getValue() == null) {
                continue;
            }

            for (String value : entry.getValue()) {

                if (value == null) {
                    value = "";
                }

                try {
                    String encodedKey = URLEncoder.encode(entry.getKey(), CHARSET);
                    String encodedValue = URLEncoder.encode(value, CHARSET);

                    if (sb.length() > 0) {
                        sb.append('&');
                    }

                    sb.append(encodedKey);
                    sb.append('=');
                    sb.append(encodedValue);

                } catch (UnsupportedEncodingException e) {

                    // UTF-8 should always be supported
                    throw new RuntimeException(e.getMessage(), e);
                }
            }
        }

        return sb.toString();
    }


    /**
     * Serialises the specified map of parameters into a URL query string.
     * Supports multiple key / value pairs that have the same key. The
     * parameter keys and values are
     * {@code application/x-www-form-urlencoded} encoded.
     *
     * <p>Note that the '?' character preceding the query string in GET
     * requests is not included in the returned string.
     *
     * <p>Example query string:
     *
     * <pre>
     * response_type=code
     * &amp;client_id=s6BhdRkqt3
     * &amp;state=xyz
     * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
     * </pre>
     *
     * <p>The opposite method is {@link #parseParameters}.
     *
     * @param params A map of the URL query parameters. May be empty or
     *               {@code null}.
     * @return The serialised URL query string, empty if no parameters.
     */
    public static String serializeParametersAlt(Map<String, String[]> params) {

        if (params == null) {
            return serializeParameters(null);
        }

        Map<String, List<String>> out = new HashMap<>();

        for (Map.Entry<String, String[]> entry : params.entrySet()) {
            if (entry.getValue() == null) {
                out.put(entry.getKey(), null);
            } else {
                out.put(entry.getKey(), Arrays.asList(entry.getValue()));
            }
        }

        return serializeParameters(out);
    }


    /**
     * Parses the specified URL query string into a parameter map. If a
     * parameter has multiple values only the first one will be saved. The
     * parameter keys and values are
     * {@code application/x-www-form-urlencoded} decoded.
     *
     * <p>Note that the '?' character preceding the query string in GET
     * requests must not be included.
     *
     * <p>Example query string:
     *
     * <pre>
     * response_type=code
     * &amp;client_id=s6BhdRkqt3
     * &amp;state=xyz
     * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
     * </pre>
     *
     * <p>The opposite method {@link #serializeParameters}.
     *
     * @param query The URL query string to parse. May be {@code null}.
     * @return A map of the URL query parameters, empty if none are found.
     */
    public static Map<String, List<String>> parseParameters(String query) {

        Map<String, List<String>> params = new HashMap<>();

        if (StringUtils.isEmpty(query)) {
            return params; // empty map
        }

        try {
            StringTokenizer st = new StringTokenizer(query.trim(), "&");

            while (st.hasMoreTokens()) {

                String param = st.nextToken();

                String[] pair = param.split("=", 2); // Split around the first '=', see issue #169

                String key = URLDecoder.decode(pair[0], CHARSET);

                String value = pair.length > 1 ? URLDecoder.decode(pair[1], CHARSET) : "";

                if (params.containsKey(key)) {
                    // Append value
                    List<String> updatedValueList = new LinkedList<>(params.get(key));
                    updatedValueList.add(value);
                    params.put(key, Collections.unmodifiableList(updatedValueList));
                } else {
                    params.put(key, Collections.singletonList(value));
                }
            }

        } catch (UnsupportedEncodingException e) {

            // UTF-8 should always be supported
        }

        return params;
    }


    /**
     * Prevents public instantiation.
     */
    private URLUtils() {
    }
}
