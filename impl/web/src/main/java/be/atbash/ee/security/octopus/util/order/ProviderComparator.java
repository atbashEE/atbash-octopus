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
package be.atbash.ee.security.octopus.util.order;

import java.util.Comparator;

/**
 *
 */
public class ProviderComparator implements Comparator<RealmProvider> {
    @Override
    public int compare(RealmProvider rp1, RealmProvider rp2) {
        Integer order1 = getOrder(rp1);
        Integer order2 = getOrder(rp2);
        return order1.compareTo(order2);
    }

    private Integer getOrder(RealmProvider configurationPlugin) {
        int result = 1000;
        Class<? extends RealmProvider> aClass = configurationPlugin.getClass();
        ProviderOrder order = aClass.getAnnotation(ProviderOrder.class);
        if (order == null && aClass.getSuperclass() != null) {
            // When we have a proxy, we have to check the superclass.
            order = aClass.getSuperclass().getAnnotation(ProviderOrder.class);
        }
        if (order != null) {
            result = order.value();
        }
        return result;
    }
}
