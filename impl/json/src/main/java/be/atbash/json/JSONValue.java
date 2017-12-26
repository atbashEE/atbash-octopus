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

import be.atbash.json.parser.JSONParser;
import be.atbash.json.parser.ParseException;
import be.atbash.json.reader.JSONWriter;
import be.atbash.json.reader.JsonWriterI;
import be.atbash.json.style.JSONStyle;
import be.atbash.json.writer.FakeMapper;
import be.atbash.json.writer.JSONReader;
import be.atbash.json.writer.Mapper;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * JSONValue is the helper class In most of case you should use those static
 * methode to use JSON-smart
 * <p>
 * <p>
 * The most commonly use methode are {@link #parse(String)}
 * {@link #toJSONString(Object)}
 *
 * @author Uriel Chemouni &lt;uchemouni@gmail.com&gt;
 * @author Rudy De Busscher
 */
public class JSONValue {

    /**
     * Serialisation class Data
     */
    public final static JSONWriter defaultWriter = new JSONWriter();
    /**
     * deserialisation class Data
     */
    public final static JSONReader defaultReader = new JSONReader();

    /**
     * Parse input json as a mapTo class
     * <p>
     * mapTo can be a bean
     *
     * @since 2.0
     */
    public static <T> T parse(String in, Class<T> mapTo) {
        JSONParser p = new JSONParser();
        return p.parse(in, defaultReader.getMapper(mapTo));
    }

    /**
     * Parse JSON text into java object from the input source.
     *
     * @return Instance of the following: JSONObject, JSONArray, String,
     * java.lang.Number, java.lang.Boolean, null
     * @see JSONParser#parse(String)
     */
    public static Object parse(String s) {
        return new JSONParser().parse(s);
    }

    /**
     * Check Json Syntax from input String
     *
     * @return if the input is valid
     */
    public static boolean isValidJson(String s) {
        try {
            new JSONParser().parse(s, FakeMapper.DEFAULT);
            return true;
        } catch (ParseException e) {
            return false;
        }
    }

    /**
     * Register a serializer for a class.
     */
    public static <T> void registerWriter(Class<?> cls, JsonWriterI<T> writer) {
        defaultWriter.registerWriter(writer, cls);
    }

    /**
     * register a deserializer for a class.
     */
    public static <T> void registerReader(Class<T> type, Mapper<T> mapper) {
        defaultReader.registerReader(type, mapper);
    }

    /**
     * Encode an object into JSON text and write it to out.
     * <p>
     * If this object is a Map or a List, and it's also a JSONStreamAware or a
     * JSONAware, JSONStreamAware or JSONAware will be considered firstly.
     * <p>
     *
     * @see JSONObject#writeJSON(Map, Appendable)
     * @see JSONArray#writeJSONString(List, Appendable)
     */
    @SuppressWarnings("unchecked")
    public static void writeJSONString(Object value, Appendable out) throws IOException {
        if (value == null) {
            out.append("null");
            return;
        }
        Class<?> clz = value.getClass();
        @SuppressWarnings("rawtypes")
        JsonWriterI w = defaultWriter.getWriter(clz);
        if (w == null) {
            if (clz.isArray()) {
                w = JSONWriter.arrayWriter;
            } else {
                w = defaultWriter.getWriterByInterface(value.getClass());
                if (w == null) {
                    w = JSONWriter.beansWriter;
                }
            }
            defaultWriter.registerWriter(w, clz);
        }
        w.writeJSONString(value, out);
    }

    /**
     * Convert an object to JSON text.
     * <p>
     * If this object is a Map or a List, and it's also a JSONAware, JSONAware
     * will be considered firstly.
     * <p>
     * DO NOT call this method from toJSONString() of a class that implements
     * both JSONAware and Map or List with "this" as the parameter, use
     * JSONObject.toJSONString(Map) or JSONArray.toJSONString(List) instead.
     *
     * @return JSON text, or "null" if value is null or it's an NaN or an INF
     * number.
     * @see JSONObject#toJSONString(Map)
     * @see JSONArray#toJSONString(List)
     */
    public static String toJSONString(Object value) {
        StringBuilder sb = new StringBuilder();
        try {
            writeJSONString(value, sb);
        } catch (IOException e) {
            // can not append on a StringBuilder
        }
        return sb.toString();
    }

    /**
     * Escape quotes, \, /, \r, \n, \b, \f, \t and other control characters
     * (U+0000 through U+001F).
     */
    public static String escape(String s) {
        if (s == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        JSONStyle.DEFAULT.escape(s, sb);
        return sb.toString();
    }

    public static void escape(String s, Appendable ap) {
        if (s == null) {
            return;
        }
        JSONStyle.DEFAULT.escape(s, ap);
    }
}
