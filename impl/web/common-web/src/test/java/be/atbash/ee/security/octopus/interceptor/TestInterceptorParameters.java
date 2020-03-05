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
package be.atbash.ee.security.octopus.interceptor;

public class TestInterceptorParameters {

    private boolean authenticated;
    private String permission;
    private boolean customAccess;
    private String systemAccount;
    private String role;

    public TestInterceptorParameters(boolean authenticated, String permission, boolean customAccess, String systemAccount, String role) {
        this.authenticated = authenticated;
        this.permission = permission;
        this.customAccess = customAccess;
        this.systemAccount = systemAccount;
        this.role = role;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public String getPermission() {
        return permission;
    }

    public boolean isCustomAccess() {
        return customAccess;
    }

    public String getSystemAccount() {
        return systemAccount;
    }

    public String getRole() {
        return role;
    }

    @Override
    public String toString() {
        return "TestInterceptorParameters{" +
                "authenticated=" + authenticated +
                ", permission='" + permission + '\'' +
                ", customAccess=" + customAccess +
                ", systemAccount='" + systemAccount + '\'' +
                ", role='" + role + '\'' +
                '}';
    }
}
