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
package be.atbash.json;

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

import be.atbash.json.reader.JSONWriter;
import be.atbash.json.style.JSONStyle;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * A JSON object. Key value pairs are unordered. JSONObject supports
 * java.util.Map interface.
 *
 * @author FangYidong &lt;fangyidong@yahoo.com.cn&gt;
 * @author Uriel Chemouni &lt;uchemouni@gmail.com&gt;
 */
public class JSONObject extends HashMap<String, Object> implements JSONAware {

    public JSONObject() {
        super();
    }


    /**
     * Allows creation of a JSONObject from a Map. After that, both the
     * generated JSONObject and the Map can be modified independently.
     */
    public JSONObject(Map<String, ?> map) {
        super(map);
    }


    /**
     * Puts value to object and returns this.
     * Handy alternative to put(String key, Object value) method.
     *
     * @param fieldName  key with which the specified value is to be associated
     * @param fieldValue value to be associated with the specified key
     * @return this
     */
    public JSONObject appendField(String fieldName, Object fieldValue) {
        put(fieldName, fieldValue);
        return this;
    }

    /**
     * A Simple Helper object to String
     *
     * @return a value.toString() or null
     */
    public String getAsString(String key) {
        Object obj = this.get(key);
		if (obj == null) {
			return null;
		}
        return obj.toString();
    }

    /**
     * A Simple Helper cast an Object to an Number
     *
     * @return a Number or null
     */
    public Number getAsNumber(String key) {
        Object obj = this.get(key);
		if (obj == null) {
			return null;
		}
		if (obj instanceof Number) {
			return (Number) obj;
		}
        return Long.valueOf(obj.toString());
    }

    /**
     * serialize Object as json to an stream
     */
    public void writeJSONString(Appendable out) throws IOException {
        writeJSON(this, out);
    }

    public void merge(Object o2) {
        merge(this, o2);
    }

    public String toJSONString() {
        return toJSONString(this);
    }

    public String toString() {
        return toJSONString(this);
    }

    /**
     * Convert a map to JSON text. The result is a JSON object. If this map is
     * also a JSONAware, JSONAware specific behaviours will be omitted at this
     * top level.
     *
     * @param map
     * @return JSON text, or "null" if map is null.
     * @see JSONValue#toJSONString(Object)
     */
    public static String toJSONString(Map<String, ?> map) {
        StringBuilder sb = new StringBuilder();
        try {
            writeJSON(map, sb);
        } catch (IOException e) {
            // can not append on a StringBuilder
        }
        return sb.toString();
    }

    /**
     * Write a Key : value entry to a stream
     */
    public static void writeJSONKV(String key, Object value, Appendable out) throws IOException {
        if (key == null) {
            out.append("null");
        } else {
            out.append('"');
            JSONValue.escape(key, out);
            out.append('"');
        }
        out.append(':');
        if (value instanceof String) {
            JSONStyle.DEFAULT.writeString(out, (String) value);
        } else {
            JSONValue.writeJSONString(value, out);
        }
    }

    /**
     * Encode a map into JSON text and write it to out. If this map is also a
     * JSONAware or JSONStreamAware, JSONAware or JSONStreamAware specific
     * behaviours will be ignored at this top level.
     *
     * @see JSONValue#writeJSONString(Object, Appendable)
     */
    public static void writeJSON(Map<String, ?> map, Appendable out)
            throws IOException {
        if (map == null) {
            out.append("null");
            return;
        }
        JSONWriter.JSONMapWriter.writeJSONString(map, out);
    }

    protected static JSONObject merge(JSONObject o1, Object o2) {
		if (o2 == null) {
			return o1;
		}
		if (o2 instanceof JSONObject) {
			return merge(o1, (JSONObject) o2);
		}
        throw new RuntimeException("JSON megre can not merge JSONObject with " + o2.getClass());
    }

    private static JSONObject merge(JSONObject o1, JSONObject o2) {
		if (o2 == null) {
			return o1;
		}
        for (String key : o1.keySet()) {
            Object value1 = o1.get(key);
            Object value2 = o2.get(key);
			if (value2 == null) {
				continue;
			}
            if (value1 instanceof JSONArray) {
                o1.put(key, merge((JSONArray) value1, value2));
                continue;
            }
            if (value1 instanceof JSONObject) {
                o1.put(key, merge((JSONObject) value1, value2));
                continue;
            }
			if (value1.equals(value2)) {
				continue;
			}
			if (value1.getClass().equals(value2.getClass())) {
				throw new RuntimeException("JSON merge can not merge two " + value1.getClass().getName() + " Object together");
			}
            throw new RuntimeException("JSON merge can not merge " + value1.getClass().getName() + " with " + value2.getClass().getName());
        }
        for (String key : o2.keySet()) {
			if (o1.containsKey(key)) {
				continue;
			}
            o1.put(key, o2.get(key));
        }
        return o1;
    }

    protected static JSONArray merge(JSONArray o1, Object o2) {
		if (o2 == null) {
			return o1;
		}
		if (o1 instanceof JSONArray) {
			return merge(o1, (JSONArray) o2);
		}
        o1.add(o2);
        return o1;
    }

    private static JSONArray merge(JSONArray o1, JSONArray o2) {
        o1.addAll(o2);
        return o1;
    }

}
