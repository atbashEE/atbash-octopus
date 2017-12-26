/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.subview.model;

/**
 *
 */

public class JWKItem {

    private String kid;
    private String keyType;
    private boolean privatePart;
    private String keyUse;

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    public boolean isPrivatePart() {
        return privatePart;
    }

    public void setPrivatePart(boolean privatePart) {
        this.privatePart = privatePart;
    }

    public String getKeyUse() {
        return keyUse;
    }

    public void setKeyUse(String keyUse) {
        this.keyUse = keyUse;
    }
}
