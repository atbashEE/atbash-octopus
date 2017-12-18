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
package be.atbash.json.writer;

/*
 *    Copyright 2011-2014 JSON-SMART authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import be.atbash.json.JSONArray;
import be.atbash.json.JSONAware;
import be.atbash.json.JSONObject;

/**
 * Simple Reader Class for generic Map
 *
 * @param <T>
 * @author uriel
 */
public class DefaultMapper<T> extends JsonReaderI<T> {
    protected DefaultMapper(JSONReader base) {
        super(base);
    }

    @Override
    public JsonReaderI<JSONAware> startObject(String key) {
        return base.DEFAULT;
    }

    @Override
    public JsonReaderI<JSONAware> startArray(String key) {
        return base.DEFAULT;
    }

    @Override
    public Object createObject() {
        return new JSONObject();
    }

    @Override
    public Object createArray() {
        return new JSONArray();
    }

    @Override
    public void setValue(Object current, String key, Object value) {
        ((JSONObject) current).put(key, value);
    }

    @Override
    public void addValue(Object current, Object value) {
        ((JSONArray) current).add(value);
    }

}
