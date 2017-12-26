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
 *    Copyright 2011 JSON-SMART authors
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

public class FakeMapper extends Mapper<Object> {
    private FakeMapper() {
        super(null);
    }

    public static Mapper<Object> DEFAULT = new FakeMapper();

    @Override
    public Mapper<?> startObject(String key) {
        return this;
    }

    @Override
    public Mapper<?> startArray(String key) {
        return this;
    }

    @Override
    public void setValue(Object current, String key, Object value) {
    }

    @Override
    public void addValue(Object current, Object value) {
    }

    @Override
    public Object createObject() {
        return null;
    }

    @Override
    public Object createArray() {
        return null;
    }
}
