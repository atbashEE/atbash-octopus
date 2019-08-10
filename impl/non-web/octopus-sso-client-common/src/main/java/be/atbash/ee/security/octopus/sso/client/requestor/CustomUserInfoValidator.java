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
package be.atbash.ee.security.octopus.sso.client.requestor;

import be.atbash.ee.security.octopus.sso.client.OpenIdVariableClientData;
import be.atbash.util.PublicAPI;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.util.List;

/**
 *
 */
@PublicAPI
public interface CustomUserInfoValidator {

    /**
     * Custom validation of the User information retrieved from the User OIDC endpoint. Additional checks can be performed
     * and Added to the list of claims with issues (return vaue !!). It is allowed to remove items from the list.
     * @param userInfo received claims from the OIDC server
     * @param variableClientData Client data (state, nonce, rootURL) -> filled only for Web Application client.
     * @param claimsWithIssues claims with issues as defined by the system already.
     * @return Updated list of claims with issues.
     */
    List<String> validateUserInfo(UserInfo userInfo, OpenIdVariableClientData variableClientData, List<String> claimsWithIssues);
}
