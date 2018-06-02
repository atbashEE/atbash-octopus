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
package be.atbash.ee.security.octopus.subject;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.util.CollectionUtils;
import be.atbash.util.PublicAPI;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.*;

/**
 * A collection of all principals associated with a corresponding {@link Subject Subject}.  A <em>principal</em> is
 * just a security term for an identifying attribute, such as a username or user id or social security number or
 * anything else that can be considered an 'identifying' attribute for a {@code Subject}.
 * <p/>
 * The primary Principal is always an instance of Octopus {@link UserPrincipal userPrincipal}. Additional principals are the {@code ValidatedAuthenticationToken} ones
 * used for creating the UserPrincipal, or derived from the UserPrincipal.
 *
 * @see #getPrimaryPrincipal()
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.subject.PrincipalCollection", "org.apache.shiro.subject.SimplePrincipalCollection"})
@PublicAPI
public class PrincipalCollection implements Iterable, Serializable {

    private Set<Serializable> principals;

    private transient String cachedToString; //cached toString() result, as this can be printed many times in logging

    public PrincipalCollection(UserPrincipal primaryPrincipal) {
        if (primaryPrincipal == null) {
            throw new AtbashIllegalActionException("(???TODO) UserPrincipal can never be null when creating the PrincipalCollection");
        }
        principals = new HashSet<>();
        principals.add(primaryPrincipal);
    }

    /**
     * Add an additional Principal to the collection.
     *
     * @param principal
     */
    public void add(Serializable principal) {
        // FIXME Should parameter be ValidatedAuthenticationToken or do we allow that developers add their own Principal.
        // Probably the second option is best and thus we need Object as type.
        if (principal == null) {
            throw new IllegalArgumentException("principal argument cannot be null.");
        }
        cachedToString = null;
        // TODO Check if a principal of the same type already exist? What about byType which can return more then one?
        principals.add(principal);
    }

    /**
     * Returns the primary principal used application-wide to uniquely identify the owning account/Subject.
     * <p/>
     * The value is always a {@link UserPrincipal userPrincipal} instance where the id is an identifying attribute specific to the data source that retrieved the
     * account data.  Some examples:
     * <ul>
     * <li>a {@link java.util.UUID UUID}</li>
     * <li>a {@code long} value such as a surrogate primary key in a relational database</li>
     * <li>an LDAP UUID or static DN</li>
     * <li>a String username unique across all user accounts</li>
     * </ul>
     *
     * @return the primary principal used to uniquely identify the owning account/Subject
     */

    public UserPrincipal getPrimaryPrincipal() {
        return oneByType(UserPrincipal.class);
    }

    /**
     * Returns the first discovered principal assignable from the specified type, or {@code null} if there are none
     * of the specified type.
     * <p/>
     * Note that this will return {@code null} if the 'owning' subject has not yet logged in.
     *
     * @param type the type of the principal that should be returned.
     * @return a principal of the specified type or {@code null} if there isn't one of the specified type.
     */
    public <T> T oneByType(Class<T> type) {
        if (CollectionUtils.isEmpty(principals)) {
            return null;
        }
        for (Object principal : principals) {
            if (type.isAssignableFrom(principal.getClass())) {
                return (T) principal;
            }
        }
        return null;
    }

    /**
     * Returns all principals assignable from the specified type, or an empty Collection if no principals of that
     * type are contained.
     * <p/>
     * Note that this will return an empty Collection if the 'owning' subject has not yet logged in.
     *
     * @param type the type of the principals that should be returned.
     * @return a Collection of principals that are assignable from the specified type, or
     * an empty Collection if no principals of this type are associated.
     */
    public <T> Collection<T> byType(Class<T> type) {
        if (CollectionUtils.isEmpty(principals)) {
            return Collections.EMPTY_SET;
        }
        Set<T> result = new HashSet<>();
        for (Object principal : principals) {
            if (type.isAssignableFrom(principal.getClass())) {
                result.add((T) principal);
            }
        }

        if (result.isEmpty()) {
            return Collections.EMPTY_SET;
        }
        return Collections.unmodifiableSet(result);

    }

    /*
     * Returns a single Subject's principals retrieved from all configured Realms as a List, or an empty List if
     * there are not any principals.
     * <p/>
     * Note that this will return an empty List if the 'owning' subject has not yet logged in.
     *
     * @return a single Subject's principals retrieved from all configured Realms as a List.

    List asList();
     */

    /**
     * Returns a single Subject's principals retrieved from all configured Realms as a Set, or an empty Set if there
     * are not any principals.
     * <p/>
     * Note that this will return an empty Set if the 'owning' subject has not yet logged in.
     *
     * @return a single Subject's principals retrieved from all configured Realms as a Set.
     */
    public Set<Serializable> asSet() {
        if (CollectionUtils.isEmpty(principals)) {
            return Collections.EMPTY_SET;
        }
        return Collections.unmodifiableSet(principals);
    }

    /**
     * Returns {@code true} if this collection is empty, {@code false} otherwise.
     *
     * @return {@code true} if this collection is empty, {@code false} otherwise.
     */
    public boolean isEmpty() {
        return CollectionUtils.isEmpty(principals);
    }

    public void clear() {
        cachedToString = null;
        if (principals != null) {
            principals.clear();
            principals = null;
        }
    }

    public Iterator iterator() {
        return asSet().iterator();
    }

    /**
     * Returns a simple string representation suitable for printing.
     *
     * @return a simple string representation suitable for printing.
     */
    public String toString() {
        if (cachedToString == null) {
            if (!CollectionUtils.isEmpty(principals)) {
                cachedToString = StringUtils.toDelimitedString(principals.toArray());
            } else {
                cachedToString = "empty";
            }
        }
        return cachedToString;
    }

    /**
     * Serialization write support.
     * <p/>
     * NOTE: Don't forget to change the serialVersionUID constant at the top of this class
     * if you make any backwards-incompatible serializatoin changes!!!
     * (use the JDK 'serialver' program for this) // FIXME Note from Shiro, is principalColleciton still stored?
     *
     * @param out output stream provided by Java serialization
     * @throws IOException if there is a stream error
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        boolean principalsExist = !CollectionUtils.isEmpty(principals);
        out.writeBoolean(principalsExist);
        if (principalsExist) {
            out.writeObject(principals);
        }
    }

    /**
     * Serialization read support - reads in the Map principals collection if it exists in the
     * input stream.
     * <p/>
     * NOTE: Don't forget to change the serialVersionUID constant at the top of this class
     * if you make any backwards-incompatible serialization changes!!!
     * (use the JDK 'serialver' program for this)
     *
     * @param in input stream provided by
     * @throws IOException            if there is an input/output problem
     * @throws ClassNotFoundException if the underlying Map implementation class is not available to the classloader.
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        boolean principalsExist = in.readBoolean();
        if (principalsExist) {
            principals = (Set) in.readObject();
        }
    }

}
