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
package be.atbash.ee.oauth2.sdk.util;


import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Multi-valued map utilities.
 */
public final class MultivaluedMapUtils {


    /**
     * Converts the specified multi-valued map to a single-valued map by
     * taking the first value in the list.
     *
     * @param map The multi-valued map, {@code null} if not specified.
     * @return The single-valued map, {@code null} if no map was specified.
     */
    public static <K, V> Map<K, V> toSingleValuedMap(final Map<K, List<V>> map) {

        if (map == null) {
            return null;
        }

        Map<K, V> out = new HashMap<>();

        for (Map.Entry<K, List<V>> en : map.entrySet()) {

            if (en.getValue() == null || en.getValue().isEmpty()) {
                out.put(en.getKey(), null);
            } else {
                out.put(en.getKey(), en.getValue().get(0));
            }
        }

        return out;
    }


    /**
     * Gets the first value for the specified key.
     *
     * @param map The multi-valued map. Must not be {@code null}.
     * @param key The key. Must not be {@code null}.
     * @return The first value, {@code null} if not set.
     */
    public static <K, V> V getFirstValue(final Map<K, List<V>> map, final K key) {

        List<V> valueList = map.get(key);

        if (valueList == null || valueList.isEmpty()) {
            return null;
        }

        return valueList.get(0);
    }


    /**
     * Removes the entry for the specified key and returns its first value.
     *
     * @param map The multi-valued map. Must not be {@code null}.
     * @param key The key. Must not be {@code null}.
     * @return The first value, {@code null} if not set.
     */
    public static <K, V> V removeAndReturnFirstValue(final Map<K, List<V>> map, final String key) {

        List<V> valueList = map.remove(key);

        if (valueList == null || valueList.isEmpty()) {
            return null;
        }

        return valueList.get(0);
    }


    /**
     * Prevents public instantiation.
     */
    private MultivaluedMapUtils() {
    }
}
