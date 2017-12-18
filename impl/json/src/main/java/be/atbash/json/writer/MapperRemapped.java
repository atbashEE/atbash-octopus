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

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

/**
 * Simple solution to supporr on read filed renaming
 *
 * @param <T>
 * @author uriel
 */
public class MapperRemapped<T> extends JsonReaderI<T> {
	private Map<String, String> rename;
    private JsonReaderI<T> parent;

    public MapperRemapped(JsonReaderI<T> parent) {
        super(parent.base);
        this.parent = parent;
        this.rename = new HashMap<>();
    }

    public void renameField(String source, String dest) {
        rename.put(source, dest);
    }

    private String rename(String key) {
        String k2 = rename.get(key);
		if (k2 != null) {
			return k2;
		}
        return key;
    }

    @Override
    public void setValue(Object current, String key, Object value) throws IOException {
        key = rename(key);
        parent.setValue(current, key, value);
    }

    public Object getValue(Object current, String key) {
        key = rename(key);
        return parent.getValue(current, key);
    }

    @Override
    public Type getType(String key) {
        key = rename(key);
        return parent.getType(key);
    }

    @Override
    public JsonReaderI<?> startArray(String key) throws IOException {
        key = rename(key);
        return parent.startArray(key);
    }

    @Override
    public JsonReaderI<?> startObject(String key) throws IOException {
        key = rename(key);
        return parent.startObject(key);
    }

    @Override
    public Object createObject() {
        return parent.createObject();
    }
}
