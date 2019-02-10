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
package be.atbash.ee.security.octopus.token;

/**
 * When a SystemAuthenticationToken is found to be valid (AuthenticationInfo is available), no other AuthenticationProvider
 * will be consulted (and thus probably other REQUIRED providers are skipped) This is required for the
 * 2 step authentication for example for the OTPToken (which do no have a Valid value for the usernamePassword based Provider as it will never be the case.)
 */
public interface SystemAuthenticationToken extends AuthenticationToken {
}
