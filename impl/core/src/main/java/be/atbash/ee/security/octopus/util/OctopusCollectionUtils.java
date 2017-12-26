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
package be.atbash.ee.security.octopus.util;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;

/**
 * Static helper class for use dealing with Collections.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.util.CollectionUtils"})
public final class OctopusCollectionUtils {

    private OctopusCollectionUtils() {
    }

    /**
     * Returns {@code true} if the specified {@code PrincipalCollection} is {@code null} or
     * {@link PrincipalCollection#isEmpty empty}, {@code false} otherwise.
     *
     * @param principals the principals to check.
     * @return {@code true} if the specified {@code PrincipalCollection} is {@code null} or
     * {@link PrincipalCollection#isEmpty empty}, {@code false} otherwise.
     */
    public static boolean isEmpty(PrincipalCollection principals) {
        return principals == null || principals.isEmpty();
    }

}
