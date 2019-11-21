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
package be.atbash.ee.langtag;

import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.JsonObject;
import javax.json.JsonValue;
import java.util.*;

public final class LangTagUtils {

    public static String strip(String s) {
        if (s == null) {
            return null;
        } else {
            int pos = s.indexOf(35);
            return pos < 0 ? s : s.substring(0, pos);
        }
    }

    public static Set<String> strip(Set<String> set) {
        if (set == null) {
            return null;
        } else {
            Set<String> out = new HashSet<>();

            for (String s : set) {
                out.add(strip(s));
            }

            return out;
        }
    }

    public static List<String> strip(List<String> list) {
        if (list == null) {
            return null;
        } else {
            List<String> out = new ArrayList<>();

            for (String s : list) {
                out.add(strip(s));
            }

            return out;
        }
    }

    public static LangTag extract(String s) throws LangTagException {
        if (s == null) {
            return null;
        } else {
            int pos = s.indexOf(35);
            return pos >= 0 && s.length() >= pos + 1 ? LangTag.parse(s.substring(pos + 1)) : null;
        }
    }

    public static <T> Map<LangTag, T> find(String baseName, JsonObject jsonObject) {
        Map<LangTag, T> result = new HashMap<>();

        for (Map.Entry<String, JsonValue> entry : jsonObject.entrySet()) {

            JsonValue value;
            try {
                value = entry.getValue();
            } catch (ClassCastException var10) {
                continue;
            }

            if (((Map.Entry) entry).getKey().equals(baseName)) {
                result.put( null, (T) JSONObjectUtils.getJsonValueAsObject(value));
            } else if (((String) ((Map.Entry) entry).getKey()).startsWith(baseName + '#')) {
                String[] parts = ((String) ((Map.Entry) entry).getKey()).split("#", 2);
                LangTag langTag = null;
                if (parts.length == 2) {
                    try {
                        langTag = LangTag.parse(parts[1]);
                    } catch (LangTagException var9) {
                    }
                }

                result.put(langTag, (T) JSONObjectUtils.getJsonValueAsObject(value));
            }
        }

        return result;
    }

    public static List<String> toStringList(Collection<LangTag> langTags) {
        if (langTags == null) {
            return null;
        } else {
            List<String> out = new ArrayList<>();

            for (LangTag lt : langTags) {
                out.add(lt.toString());
            }

            return out;
        }
    }

    public static String[] toStringArray(Collection<LangTag> langTags) {
        if (langTags == null) {
            return null;
        } else {
            String[] out = new String[langTags.size()];
            int i = 0;

            LangTag lt;
            for (Iterator var3 = langTags.iterator(); var3.hasNext(); out[i++] = lt.toString()) {
                lt = (LangTag) var3.next();
            }

            return out;
        }
    }

    public static List<LangTag> parseLangTagList(Collection<String> collection) throws LangTagException {
        if (collection == null) {
            return null;
        } else {
            List<LangTag> out = new ArrayList<>();

            for (String s : collection) {
                out.add(LangTag.parse(s));
            }

            return out;
        }
    }

    public static List<LangTag> parseLangTagList(String... values) throws LangTagException {
        if (values == null) {
            return null;
        }
        List<LangTag> out = new ArrayList<>();

        for (String s : values) {
            out.add(LangTag.parse(s));
        }

        return out;

    }

    public static LangTag[] parseLangTagArray(String... values) throws LangTagException {
        if (values == null) {
            return null;
        } else {
            LangTag[] out = new LangTag[values.length];

            for (int i = 0; i < values.length; ++i) {
                out[i] = LangTag.parse(values[i]);
            }

            return out;
        }
    }

    private LangTagUtils() {
    }
}
