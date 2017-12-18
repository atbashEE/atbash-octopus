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
package be.atbash.ee.security.octopus.jwt.decoder;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */

public class MetaJWTData {

    private String keyID;
    private Map<String, Object> headerValues;

    public MetaJWTData() {
        headerValues = new HashMap<>();
    }

    public MetaJWTData(String keyID, Map<String, Object> headerValues) {
        this.keyID = keyID;
        this.headerValues = headerValues;
    }

    public String getKeyID() {
        return keyID;
    }

    public Map<String, Object> getHeaderValues() {
        return headerValues;
    }


}
