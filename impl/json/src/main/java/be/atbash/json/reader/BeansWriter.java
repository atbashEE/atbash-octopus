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
package be.atbash.json.reader;

import be.atbash.json.JSONObject;
import be.atbash.json.JSONUtil;
import be.atbash.json.style.JSONStyle;
import net.minidev.asm.Accessor;
import net.minidev.asm.BeansAccess;

import java.io.IOException;

// This is the net.minidev.BeansWriterASM
public class BeansWriter implements JsonWriterI<Object> {
    public <E> void writeJSONString(E value, Appendable out) throws IOException {
        Class<?> cls = value.getClass();
        boolean needSep = false;
        @SuppressWarnings("rawtypes")
        BeansAccess fields = BeansAccess.get(cls, JSONUtil.JSON_SMART_FIELD_FILTER);
        out.append('{');
        for (Accessor field : fields.getAccessors()) {
            @SuppressWarnings("unchecked")
            Object v = fields.get(value, field.getIndex());
            if (v == null && JSONStyle.DEFAULT.ignoreNull()) {
                continue;
            }
            if (needSep) {
                out.append(',');
            } else {
                needSep = true;
            }
            String key = field.getName();
            JSONObject.writeJSONKV(key, v, out);
        }
        out.append('}');
    }
}
