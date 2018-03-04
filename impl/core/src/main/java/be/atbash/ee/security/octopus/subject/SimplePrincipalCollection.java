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
import be.atbash.util.StringUtils;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.*;

/**
 * A simple implementation of the {@link MutablePrincipalCollection} interface that tracks principals internally
 * by storing them in a {@link LinkedHashMap}.
 */
@SuppressWarnings({"unchecked"})
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.subject.SimplePrincipalCollection"})
public class SimplePrincipalCollection implements PrincipalCollection /*implements MutablePrincipalCollection Since we don't use multiple realms it is better to have only immutable ones */ {

    //TODO - complete JavaDoc

    //private Map<String, Set> realmPrincipals;
    private Set realmPrincipals;

    private transient String cachedToString; //cached toString() result, as this can be printed many times in logging

    public SimplePrincipalCollection() {
    }

    public SimplePrincipalCollection(Object principal) {
        if (principal instanceof Collection) {
            addAll((Collection) principal);
        } else {
            add(principal);
        }
    }

    public SimplePrincipalCollection(Collection principals) {
        addAll(principals);
    }

    public SimplePrincipalCollection(PrincipalCollection principals) {
        addAll(principals);
    }

    protected Collection getPrincipalsLazy(/*String realmName*/) {
        if (realmPrincipals == null) {
            //realmPrincipals = new LinkedHashMap<String, Set>();
            realmPrincipals = new LinkedHashSet();
        }
        /*
        Set principals = realmPrincipals.get(realmName);
        if (principals == null) {
            principals = new LinkedHashSet();
            realmPrincipals.put(realmName, principals);
        }*/
        return realmPrincipals;
    }

    /**
     * Returns the first available principal from any of the {@code Realm} principals, or {@code null} if there are
     * no principals yet.
     * <p/>
     * The 'first available principal' is interpreted as the principal that would be returned by
     * <code>{@link #iterator() iterator()}.{@link Iterator#next() next()}.</code>
     *
     * @inheritDoc
     */
    public Object getPrimaryPrincipal() {
        if (isEmpty()) {
            return null;
        }
        return iterator().next();
    }

    public void add(Object principal/*, String realmName*/) {
        /*
        if (realmName == null) {
            throw new IllegalArgumentException("realmName argument cannot be null.");
        }
        */
        if (principal == null) {
            throw new IllegalArgumentException("principal argument cannot be null.");
        }
        cachedToString = null;
        getPrincipalsLazy().add(principal);
    }

    public void addAll(Collection principals/*, String realmName*/) {
        /*
        if (realmName == null) {
            throw new IllegalArgumentException("realmName argument cannot be null.");
        }
        */
        if (principals == null) {
            throw new IllegalArgumentException("principals argument cannot be null.");
        }
        if (principals.isEmpty()) {
            throw new IllegalArgumentException("principals argument cannot be an empty collection.");
        }
        cachedToString = null;
        getPrincipalsLazy().addAll(principals);
    }

    public void addAll(PrincipalCollection principals) {
        for (Object principal : principals.asList()) {
            add(principal);
        }
        /*
        if (principals.getRealmNames() != null) {
            for (String realmName : principals.getRealmNames()) {
                for (Object principal : principals.fromRealm(realmName)) {
                    add(principal);
                }
            }
        }
        */
    }

    public <T> T oneByType(Class<T> type) {
        if (realmPrincipals == null || realmPrincipals.isEmpty()) {
            return null;
        }
        for (Object o : realmPrincipals) {
            if (type.isAssignableFrom(o.getClass())) {
                return (T) o;
            }
        }
        return null;
    }

    public <T> Collection<T> byType(Class<T> type) {
        throw new UnsupportedOperationException("TODO be.rubus.jsr375.octopus.subject.SimplePrincipalCollection.byType");
        /*
        if (realmPrincipals == null || realmPrincipals.isEmpty()) {
            return Collections.EMPTY_SET;
        }
        Set<T> typed = new LinkedHashSet<T>();
        Collection<Set> values = realmPrincipals.values();
        for (Set set : values) {
            for (Object o : set) {
                if (type.isAssignableFrom(o.getClass())) {
                    typed.add((T) o);
                }
            }
        }
        if (typed.isEmpty()) {
            return Collections.EMPTY_SET;
        }
        return Collections.unmodifiableSet(typed);
        */
    }

    public List asList() {
        Set all = asSet();
        if (all.isEmpty()) {
            return Collections.EMPTY_LIST;
        }
        return Collections.unmodifiableList(new ArrayList(all));
    }

    public Set asSet() {
        if (realmPrincipals == null || realmPrincipals.isEmpty()) {
            return Collections.EMPTY_SET;
        }
        /*
        Set aggregated = new LinkedHashSet();
        Collection<Set> values = realmPrincipals.values();
        for (Set set : values) {
            aggregated.addAll(set);
        }
        if (aggregated.isEmpty()) {
            return Collections.EMPTY_SET;
        }
        */
        return Collections.unmodifiableSet(realmPrincipals);
    }

    public boolean isEmpty() {
        return realmPrincipals == null || realmPrincipals.isEmpty();
    }

    public void clear() {
        cachedToString = null;
        if (realmPrincipals != null) {
            realmPrincipals.clear();
            realmPrincipals = null;
        }
    }

    public Iterator iterator() {
        return asSet().iterator();
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof SimplePrincipalCollection) {
            SimplePrincipalCollection other = (SimplePrincipalCollection) o;
            return realmPrincipals != null ? realmPrincipals.equals(other.realmPrincipals) : other.realmPrincipals == null;
        }
        return false;
    }

    public int hashCode() {
        if (realmPrincipals != null && !realmPrincipals.isEmpty()) {
            return realmPrincipals.hashCode();
        }
        return super.hashCode();
    }

    /**
     * Returns a simple string representation suitable for printing.
     *
     * @return a simple string representation suitable for printing.
     */
    public String toString() {
        if (cachedToString == null) {
            Set<Object> principals = asSet();
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
        boolean principalsExist = !CollectionUtils.isEmpty(realmPrincipals);
        out.writeBoolean(principalsExist);
        if (principalsExist) {
            out.writeObject(realmPrincipals);
        }
    }

    /**
     * Serialization read support - reads in the Map principals collection if it exists in the
     * input stream.
     * <p/>
     * NOTE: Don't forget to change the serialVersionUID constant at the top of this class
     * if you make any backwards-incompatible serialization changes!!!
     * (use the JDK 'serialver' program for this) // FIXME Note from Shiro, is principalColleciton still stored?
     *
     * @param in input stream provided by
     * @throws IOException            if there is an input/output problem
     * @throws ClassNotFoundException if the underlying Map implementation class is not available to the classloader.
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        boolean principalsExist = in.readBoolean();
        if (principalsExist) {
            realmPrincipals = (Set) in.readObject();
        }
    }
}
