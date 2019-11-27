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


import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;


public class URLUtilsTest {

    @Test
    public void testGetBaseURLSame()
            throws MalformedURLException {

        URL url = new URL("http://client.example.com:8080/endpoints/openid/connect/cb");

        URL baseURL = URLUtils.getBaseURL(url);

        assertThat(baseURL.toString()).isEqualTo("http://client.example.com:8080/endpoints/openid/connect/cb");
    }

    @Test
    public void testGetBaseURLTrim()
            throws MalformedURLException {

        URL url = new URL("http://client.example.com:8080/endpoints/openid/connect/cb?param1=one&param2=two");

        URL baseURL = URLUtils.getBaseURL(url);

        assertThat(baseURL.toString()).isEqualTo("http://client.example.com:8080/endpoints/openid/connect/cb");
    }

    @Test
    public void testJavaURLDecoder()
            throws Exception {

        String decodedPlus = URLDecoder.decode("abc+def", "utf-8");
        String decodedPerCent20 = URLDecoder.decode("abc%20def", "utf-8");

        assertThat(decodedPlus).isEqualTo("abc def");
        assertThat(decodedPerCent20).isEqualTo("abc def");
    }

    @Test
    public void testSerializeParameters() {

        Map<String, List<String>> params = new LinkedHashMap<>();

        params.put("response_type", Collections.singletonList("code id_token"));
        params.put("client_id", Collections.singletonList("s6BhdRkqt3"));
        params.put("redirect_uri", Collections.singletonList("https://client.example.com/cb"));
        params.put("scope", Collections.singletonList("openid"));
        params.put("nonce", Collections.singletonList("n-0S6_WzA2Mj"));
        params.put("state", Collections.singletonList("af0ifjsldkj"));

        String query = URLUtils.serializeParameters(params);

        assertThat(query).isEqualTo("response_type=code+id_token" +
                "&client_id=s6BhdRkqt3" +
                "&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
                "&scope=openid" +
                "&nonce=n-0S6_WzA2Mj" +
                "&state=af0ifjsldkj");
    }

    @Test
    public void testSerializeParameters_nullValue() {

        Map<String, List<String>> params = new LinkedHashMap<>();

        params.put("response_type", Collections.singletonList("code"));
        params.put("display", null);

        String query = URLUtils.serializeParameters(params);

        assertThat(query).isEqualTo("response_type=code");
    }

    @Test
    public void testSerializeParametersNull() {

        String query = URLUtils.serializeParameters(null);

        assertThat(query.isEmpty()).isTrue();
    }

    @Test
    public void testSerializeParameters_multiValued() {

        Map<String, List<String>> params = new LinkedHashMap<>();

        params.put("key-1", Collections.singletonList("val-1"));
        params.put("key-2", Arrays.asList("val-2a", "val-2b"));

        String query = URLUtils.serializeParameters(params);

        assertThat(query).isEqualTo("key-1=val-1&key-2=val-2a&key-2=val-2b");
    }

    @Test
    public void testParseParameters() {

        String query = "response_type=code%20id_token" +
                "&client_id=s6BhdRkqt3" +
                "&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
                "&scope=openid" +
                "&nonce=n-0S6_WzA2Mj" +
                "&state=af0ifjsldkj";

        Map<String, List<String>> params = URLUtils.parseParameters(query);

        assertThat(params.get("response_type")).isEqualTo(Collections.singletonList("code id_token"));
        assertThat(params.get("client_id")).isEqualTo(Collections.singletonList("s6BhdRkqt3"));
        assertThat(params.get("redirect_uri")).isEqualTo(Collections.singletonList("https://client.example.com/cb"));
        assertThat(params.get("scope")).isEqualTo(Collections.singletonList("openid"));
        assertThat(params.get("nonce")).isEqualTo(Collections.singletonList("n-0S6_WzA2Mj"));
        assertThat(params.get("state")).isEqualTo(Collections.singletonList("af0ifjsldkj"));
    }

    @Test
    public void testParseParametersNull() {

        assertThat(URLUtils.parseParameters(null).isEmpty()).isTrue();
    }

    @Test
    public void testParseParametersEmpty() {

        assertThat(URLUtils.parseParameters(" ").isEmpty()).isTrue();
    }

    @Test
    public void testParseParametersEnsureTrim() {

        String query = "\np1=abc&p2=def  \n";

        Map<String, List<String>> params = URLUtils.parseParameters(query);

        assertThat(params.get("p1")).isEqualTo(Collections.singletonList("abc"));
        assertThat(params.get("p2")).isEqualTo(Collections.singletonList("def"));
        assertThat(params).hasSize(2);
    }


    // See https://bitbucket.org/connect2id/openid-connect-dev-client/issues/5/stripping-equal-sign-from-access_code-in
    @Test
    public void testDecodeQueryStringWithEscapedChars() {

        String fragment = "scope=openid+email+profile" +
                "&state=cVIe4g4D1J3tYtZgnTL-Po9QpozQJdikDCBp7KJorIQ" +
                "&code=1nf1ljB0JkPIbhMcYMeoT9Q5oGt28ggDsUiWLvCL81YTqCZMzAbVCGLUPrDHouda4cELZRujcS7d8rUNcZVl7HxUXdDsOUtc65s2knGbxSo%3D";

        Map<String, List<String>> params = URLUtils.parseParameters(fragment);

        assertThat(params.get("scope")).isEqualTo(Collections.singletonList("openid email profile"));
        assertThat(params.get("state")).isEqualTo(Collections.singletonList("cVIe4g4D1J3tYtZgnTL-Po9QpozQJdikDCBp7KJorIQ"));
        assertThat(params.get("code")).isEqualTo(Collections.singletonList("1nf1ljB0JkPIbhMcYMeoT9Q5oGt28ggDsUiWLvCL81YTqCZMzAbVCGLUPrDHouda4cELZRujcS7d8rUNcZVl7HxUXdDsOUtc65s2knGbxSo="));
    }


    // See iss #169
    public void testAllowEqualsCharInParamValue() {

        String query = "key0=value&key1=value=&key2=value==&key3=value===";

        Map<String, List<String>> params = URLUtils.parseParameters(query);
        assertThat(params.get("key0")).isEqualTo(Collections.singletonList("value"));
        assertThat(params.get("key1")).isEqualTo(Collections.singletonList("value="));
        assertThat(params.get("key2")).isEqualTo(Collections.singletonList("value=="));
        assertThat(params.get("key3")).isEqualTo(Collections.singletonList("value==="));
        assertThat(params).hasSize(4);
    }

    @Test
    public void testSerializeAlt_duplicateKeys() {

        Map<String, String[]> params = new LinkedHashMap<>();

        params.put("fruit", new String[]{"apple", "orange"});
        params.put("veg", new String[]{"lettuce"});

        String s = URLUtils.serializeParametersAlt(params);

        assertThat(s).isEqualTo("fruit=apple&fruit=orange&veg=lettuce");
    }


    public void testSerializeAlt_nullValue() {

        Map<String, String[]> params = new LinkedHashMap<>();

        params.put("fruit", null);
        params.put("veg", new String[]{"lettuce"});

        String s = URLUtils.serializeParametersAlt(params);

        assertThat(s).isEqualTo("veg=lettuce");
    }

    @Test
    public void testSerializeAlt_nullValueInArray() {

        Map<String, String[]> params = new LinkedHashMap<>();

        params.put("fruit", new String[]{"apple", null});
        params.put("veg", new String[]{"lettuce"});

        String s = URLUtils.serializeParametersAlt(params);

        assertThat(s).isEqualTo("fruit=apple&fruit=&veg=lettuce");
    }
}
