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
package be.atbash.ee.security.octopus.sso.core.client;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.ResponseType;

/**
 * This are the OAuth2 flows
 */
public enum SSOFlow {
    IMPLICIT("token"), AUTHORIZATION_CODE("code");

    private String responseTypeCode;
    private ResponseType responseType;

    SSOFlow(String responseTypeCode) {
        this.responseTypeCode = responseTypeCode;
        try {
            if ("token".equals(responseTypeCode)) {
                responseType = ResponseType.parse("token id_token");
            } else {
                responseType = ResponseType.parse("code");
            }
        } catch (OAuth2JSONParseException e) {
            // Should never happen as it is developer written code
        }

    }

    public ResponseType getResponseType() {
        return responseType;
    }

    public static SSOFlow defineFlow(String responseType) {
        if (responseType == null) {
            return null;
        }
        SSOFlow result = null;
        for (SSOFlow ssoFlow : SSOFlow.values()) {
            if (responseType.equals(ssoFlow.responseTypeCode)) {
                result = ssoFlow;
            }
        }
        return result;
    }
}
