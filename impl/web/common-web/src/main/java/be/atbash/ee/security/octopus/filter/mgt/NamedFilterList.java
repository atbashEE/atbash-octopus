/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.filter.mgt;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.filter.AdviceFilter;
import be.atbash.ee.security.octopus.web.servlet.ProxiedFilterChain;
import be.atbash.util.Reviewed;
import be.atbash.util.StringUtils;

import jakarta.servlet.FilterChain;
import java.util.*;

/**
 * A {@code NamedFilterList} is a {@code List} of {@code Filter} instances that is uniquely identified by a
 * {@link #getName() name}.  It has the ability to generate new {@link FilterChain} instances reflecting this list's
 * filter order via the {@link #proxy proxy} method.
 */
@Reviewed
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.filter.mgt.NamedFilterList", "org.apache.shiro.web.filter.mgt.SimpleNamedFilterList"})
public class NamedFilterList implements List<AdviceFilter> {

    private String name;
    private List<AdviceFilter> backingList;
    private String filterNames;

    /**
     * Creates a new {@code SimpleNamedFilterList} instance with the specified {@code name}, defaulting to a new
     * {@link ArrayList ArrayList} instance as the backing list.
     *
     * @param name the name to assign to this instance.
     * @throws IllegalArgumentException if {@code name} is null or empty.
     */
    public NamedFilterList(String name) {
        backingList = new ArrayList<>();
        setName(name);
    }

    private void setName(String name) {
        if (!StringUtils.hasText(name)) {
            throw new IllegalArgumentException("Cannot specify a null or empty name.");
        }
        this.name = name;
    }

    /**
     * Returns the configuration-unique name assigned to this {@code Filter} list.
     *
     * @return the configuration-unique name assigned to this {@code Filter} list.
     */
    public String getName() {
        return name;
    }

    /**
     * Returns a new {@code FilterChain} instance that will first execute this list's {@code Filter}s (in list order)
     * and end with the execution of the given {@code filterChain} instance.
     *
     * @param orig the {@code FilterChain} instance (original from container) to execute after this list's {@code Filter}s have executed.
     * @return a new {@code FilterChain} instance that will first execute this list's {@code Filter}s (in list order)
     * and end with the execution of the given {@code filterChain} instance.
     */
    public FilterChain proxy(FilterChain orig) {
        return new ProxiedFilterChain(orig, this);
    }

    @Override
    public boolean add(AdviceFilter filter) {
        return backingList.add(filter);
    }

    @Override
    public void add(int index, AdviceFilter filter) {
        backingList.add(index, filter);
    }

    @Override
    public boolean addAll(Collection<? extends AdviceFilter> c) {
        return backingList.addAll(c);
    }

    @Override
    public boolean addAll(int index, Collection<? extends AdviceFilter> c) {
        return backingList.addAll(index, c);
    }

    @Override
    public void clear() {
        backingList.clear();
    }

    @Override
    public boolean contains(Object o) {
        return backingList.contains(o);
    }

    @Override
    public boolean containsAll(Collection<?> c) {
        return backingList.containsAll(c);
    }

    @Override
    public AdviceFilter get(int index) {
        return backingList.get(index);
    }

    @Override
    public int indexOf(Object o) {
        return backingList.indexOf(o);
    }

    @Override
    public boolean isEmpty() {
        return backingList.isEmpty();
    }

    @Override
    public Iterator<AdviceFilter> iterator() {
        return backingList.iterator();
    }

    @Override
    public int lastIndexOf(Object o) {
        return backingList.lastIndexOf(o);
    }

    @Override
    public ListIterator<AdviceFilter> listIterator() {
        return backingList.listIterator();
    }

    @Override
    public ListIterator<AdviceFilter> listIterator(int index) {
        return backingList.listIterator(index);
    }

    @Override
    public AdviceFilter remove(int index) {
        return backingList.remove(index);
    }

    @Override
    public boolean remove(Object o) {
        return backingList.remove(o);
    }

    @Override
    public boolean removeAll(Collection<?> c) {
        return backingList.removeAll(c);
    }

    @Override
    public boolean retainAll(Collection<?> c) {
        return backingList.retainAll(c);
    }

    @Override
    public AdviceFilter set(int index, AdviceFilter filter) {
        return backingList.set(index, filter);
    }

    @Override
    public int size() {
        return backingList.size();
    }

    @Override
    public List<AdviceFilter> subList(int fromIndex, int toIndex) {
        return backingList.subList(fromIndex, toIndex);
    }

    @Override
    public Object[] toArray() {
        return backingList.toArray();
    }

    @Override
    public <T> T[] toArray(T[] a) {
        //noinspection SuspiciousToArrayCall
        return backingList.toArray(a);
    }

    void listFinalFilterNames() {
        StringBuilder filterNames = new StringBuilder();
        for (AdviceFilter adviceFilter : backingList) {
            if (filterNames.length()>0) {
                filterNames.append(", ");
            }
            filterNames.append(adviceFilter.getName());
        }
        this.filterNames = filterNames.toString();
    }

    public String getFilterNames() {
        return filterNames;
    }
}
