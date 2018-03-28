/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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

import be.atbash.json.JSONArray;
import be.atbash.json.JSONAware;
import be.atbash.json.JSONObject;
import be.atbash.json.parser.MappedBy;
import be.atbash.util.reflection.ClassUtils;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class JSONReader {
    private final ConcurrentHashMap<Type, Mapper<?>> cache;

    public Mapper<JSONAware> DEFAULT;
    public Mapper<JSONAware> DEFAULT_ORDERED;

    public JSONReader() {
        cache = new ConcurrentHashMap<>(100);

        cache.put(Date.class, BeansMapper.MAPPER_DATE);

        cache.put(int[].class, ArraysMapper.MAPPER_PRIM_INT);
        cache.put(Integer[].class, ArraysMapper.MAPPER_INT);

        cache.put(short[].class, ArraysMapper.MAPPER_PRIM_INT);
        cache.put(Short[].class, ArraysMapper.MAPPER_INT);

        cache.put(long[].class, ArraysMapper.MAPPER_PRIM_LONG);
        cache.put(Long[].class, ArraysMapper.MAPPER_LONG);

        cache.put(byte[].class, ArraysMapper.MAPPER_PRIM_BYTE);
        cache.put(Byte[].class, ArraysMapper.MAPPER_BYTE);

        cache.put(char[].class, ArraysMapper.MAPPER_PRIM_CHAR);
        cache.put(Character[].class, ArraysMapper.MAPPER_CHAR);

        cache.put(float[].class, ArraysMapper.MAPPER_PRIM_FLOAT);
        cache.put(Float[].class, ArraysMapper.MAPPER_FLOAT);

        cache.put(double[].class, ArraysMapper.MAPPER_PRIM_DOUBLE);
        cache.put(Double[].class, ArraysMapper.MAPPER_DOUBLE);

        cache.put(boolean[].class, ArraysMapper.MAPPER_PRIM_BOOL);
        cache.put(Boolean[].class, ArraysMapper.MAPPER_BOOL);

        this.DEFAULT = new DefaultMapper<>(this);
        this.DEFAULT_ORDERED = new DefaultMapperOrdered(this);

        cache.put(JSONAware.class, this.DEFAULT);
        cache.put(JSONArray.class, this.DEFAULT);
        cache.put(JSONObject.class, this.DEFAULT);
    }

    public <T> void registerReader(Class<T> type, Mapper<T> mapper) {
        cache.put(type, mapper);
    }

    @SuppressWarnings("unchecked")
    public <T> Mapper<T> getMapper(Type type) {
        if (type instanceof ParameterizedType) {
            return getMapper((ParameterizedType) type);
        }
        return getMapper((Class<T>) type);
    }

    /**
     * Get the corresponding mapper Class, or create it on first call
     *
     * @param type to be map
     */
    public <T> Mapper<T> getMapper(Class<T> type) {
        // look for cached Mapper
        @SuppressWarnings("unchecked")
        Mapper<T> map = (Mapper<T>) cache.get(type);
        if (map != null) {
            return map;
        }
        /*
         * Special handle
         */
        if (type instanceof Class) {
            if (Map.class.isAssignableFrom(type)) {
                map = new DefaultMapperCollection<>(this, type);
            } else if (List.class.isAssignableFrom(type)) {
                map = new DefaultMapperCollection<>(this, type);
            }
            if (map != null) {
                cache.put(type, map);
                return map;
            }
        }

        if (type.isArray()) {
            map = new ArraysMapper.GenericMapper<>(this, type);
        } else if (List.class.isAssignableFrom(type)) {
            map = new CollectionMapper.ListClass<>(this, type);
        } else if (Map.class.isAssignableFrom(type)) {
            map = new CollectionMapper.MapClass<>(this, type);
        } else
        // use bean class
        {

            MappedBy mappedBy = type.getAnnotation(MappedBy.class);
            if (mappedBy != null) {
                if (!(mappedBy.mapper().equals(CustomMapper.NOPCustomMapper.class))) {
                    map = ClassUtils.newInstance(mappedBy.mapper(), this);
                }
            }
            if (map == null) {
                map = new BeansMapper.Bean<>(this, type);
            }
        }
        cache.putIfAbsent(type, map);
        return map;
    }

    @SuppressWarnings("unchecked")
    public <T> Mapper<T> getMapper(ParameterizedType type) {
        Mapper<T> map = (Mapper<T>) cache.get(type);
        if (map != null) {
            return map;
        }
        Class<T> clz = (Class<T>) type.getRawType();
        if (List.class.isAssignableFrom(clz)) {
            map = new CollectionMapper.ListType<>(this, type);
        } else if (Map.class.isAssignableFrom(clz)) {
            map = new CollectionMapper.MapType<>(this, type);
        }
        cache.putIfAbsent(type, map);
        return map;
    }
}
