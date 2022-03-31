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
import be.atbash.ee.security.octopus.audit.OctopusAuditFilter;
import be.atbash.ee.security.octopus.config.OctopusWebConfiguration;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.filter.AdviceFilter;
import be.atbash.ee.security.octopus.filter.GlobalFilterProvider;
import be.atbash.ee.security.octopus.filter.PathMatchingFilter;
import be.atbash.ee.security.octopus.util.order.ProviderComparator;
import be.atbash.ee.security.octopus.web.url.SecuredURLReader;
import be.atbash.util.CDIUtils;
import be.atbash.util.CollectionUtils;
import be.atbash.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import java.util.*;

import static be.atbash.ee.security.octopus.filter.authc.AnonymousFilter.ANONYMOUS_FILTER_NAME;
import static be.atbash.ee.security.octopus.filter.mgt.ExceptionFilter.EXCEPTION_FILTER_NAME;

/**
 * A {@code FilterChainManager} manages the creation and modification of {@link Filter} chains from an available pool
 * of {@link Filter} instances.
 */
@ApplicationScoped
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.filter.mgt.FilterChainManager", "org.apache.shiro.web.filter.mgt.DefaultFilterChainManager"})
public class FilterChainManager {

    private static final Logger log = LoggerFactory.getLogger(FilterChainManager.class);

    @Inject
    private OctopusWebConfiguration webConfiguration;

    @Inject
    private SecuredURLReader securedURLReader;

    @Inject
    private Instance<AdviceFilter> filterProvider;

    private Map<String, AdviceFilter> filters; //pool of filters available for creating chains
    //key: filter name, value: Filter

    private Map<String, NamedFilterList> filterChains;
    //key: chain name = URL, value: chain

    private List<GlobalFilterProvider> globalFilterProviders;

    /**
     * It initialize this class by first looking up all filters it can find as CDI Beans (all AdviceFilter implementations)
     * and then creating the actual chains which are read from the configuration file.
     */
    @PostConstruct
    public void init() {
        filters = new LinkedHashMap<>();  // TODO Review choice of LinkedHashMap by Shiro.
        filterChains = new LinkedHashMap<>();

        defineFilters();
        defineGlobalFilterProviders();
        defineChains();
    }

    private void defineGlobalFilterProviders() {

        // retrieveInstances is an unmodifiable list
        globalFilterProviders = new ArrayList<>(CDIUtils.retrieveInstances(GlobalFilterProvider.class));

        globalFilterProviders.sort(new ProviderComparator());

    }

    /**
     * Defines all the 'chains' of the applications. In other words, it defines which filters
     * will be used for a certain URL.
     * <p>
     * Specialized versions of this class can overwrite this method to define the chains in another way.
     * However, using the properties file and the {@link be.atbash.ee.security.octopus.web.url.ProgrammaticURLProtectionProvider}
     * implementations should be sufficient in almost all cases.
     */
    protected void defineChains() {
        for (Map.Entry<String, String> entry : securedURLReader.getUrlPatterns().entrySet()) {
            createChain(entry.getKey(), entry.getValue());
        }

        // At the end, we always add the anonymous access
        // TODO This in preparation for some config where we add the denied definition for al not explicitly defined paths.
        createChain("/**", ANONYMOUS_FILTER_NAME);
    }

    /**
     * Retrieve all CDI beans which are AdviceFilter implementations.
     * Specialized version of this class can overwrite this method to add filters
     * in a different way, or have the possibility to add in another way.
     * However, the preferred method is creating a class which implements {@Link AbstractFilter}
     * and define it as a CDI bean.
     */
    protected void defineFilters() {
        // protected in case someone wants to make a Specialized version

        for (AdviceFilter filter : filterProvider.select()) {
            for (String filterName : filter.getNames()) {
                addFilter(filterName, filter);
            }
        }
    }

    /**
     * Adds a filter to the 'pool' of available filters that can be used when
     * {@link #addToChain(String, String, String) creating filter chains}.
     * <p>
     * Specialized versions can call this method directly but should does this in an overwritten version of
     * the {@link #defineFilters()} method.
     *
     * @param name   the name to assign to the filter, used to reference the filter in chain definitions
     * @param filter the filter to assign to the filter pool
     */
    protected void addFilter(String name, AdviceFilter filter) {
        // protected in case someone wants to make a Specialized version
        AdviceFilter existing = getFilter(name);
        if (existing == null) {
            filters.put(name, filter);
        } else {
            //
            log.warn(String.format("(W0010) Warning : Another filter already exists with the same name. " +
                            "The new filter is not active, only the existing one (name : %s, existing : %s, new : %s",
                    name, existing.getClass().getName(), filter.getClass().getName()));
        }
    }

    /**
     * Returns the pool of available {@code Filter}s managed by this manager, keyed by {@code name}.
     *
     * @return the pool of available {@code Filter}s managed by this manager, keyed by {@code name}.
     */
    public Map<String, AdviceFilter> getFilters() {
        return filters;
    }

    /**
     * Returns the filter specified by the name within the parameter.
     *
     * @param name name of the filter to retrieve
     * @return The Filter bound to that name or null when no such filter exists.
     */
    public AdviceFilter getFilter(String name) {
        return filters.get(name);
    }

    /**
     * Creates a filter chain for the given {@code chainName} with the specified {@code chainDefinition}
     * String.
     * <h3>Conventional Use</h3>
     * Because the {@code FilterChainManager} interface does not impose any restrictions on filter chain names,
     * (it expects only Strings), a default convention is to make the chain name an actual URL path expression
     * <p>
     * The {@code chainDefinition} method argument is expected to conform to the following format:
     * <pre>
     * filter1[optional_config1], filter2[optional_config2], ..., filterN[optional_configN]</pre>
     * where
     * <ol>
     * <li>{@code filterN} is the name of a filter previously
     * {@link #addFilter(String, be.atbash.ee.security.octopus.web.servlet.AbstractFilter) registered} with the manager, and</li>
     * <li>{@code [optional_configN]} is an optional bracketed string that has meaning for that particular filter for
     * <em>this particular chain</em></li>
     * </ol>
     * If the filter does not need specific config for that chain name/URL path,
     * you may discard the brackets - that is, {@code filterN[]} just becomes {@code filterN}.
     * <p/>
     * And because this method does create a chain, remember that order matters!  The comma-delimited filter tokens in
     * the {@code chainDefinition} specify the chain's execution order.
     * <h3>Examples</h3>
     * <pre>/account/** = authcBasic</pre>
     * This example says &quot;Create a filter named '{@code /account/**}' consisting of only the '{@code authcBasic}'
     * filter&quot;.  Also because the {@code authcBasic} filter does not need any path-specific
     * config, it doesn't have any config brackets {@code []}.
     * <p/>
     * <pre>/remoting/** = authcBasic, roles[b2bClient], perms[&quot;remote:invoke:wan,lan&quot;]</pre>
     * This example by contrast uses the 'roles' and 'perms' filters which <em>do</em> use bracket notation.  This
     * definition says:
     * <p/>
     * Construct a filter chain named '{@code /remoting/**}' which
     * <ol>
     * <li>ensures the user is first authenticated ({@code authcBasic}) then</li>
     * <li>ensures that user has the {@code b2bClient} role, and then finally</li>
     * <li>ensures that they have the {@code remote:invoke:lan,wan} permission.</li>
     * </ol>
     * <p/>
     * <b>Note</b>: because elements within brackets [ ] can be comma-delimited themselves, you must quote the
     * internal bracket definition if commas are needed (the above example has 'lan,wan').  If we didn't do that, the
     * parser would interpret the chain definition as four tokens:
     * <ol>
     * <li>authcBasic</li>
     * <li>roles[b2bclient]</li>
     * <li>perms[remote:invoke:lan</li>
     * <li>wan]</li>
     * </ol>
     * which is obviously incorrect.  So remember to use quotes if your internal bracket definitions need to use commas.
     *
     * @param chainName       the name to associate with the chain, conventionally a URL path pattern.
     * @param chainDefinition the string-formatted chain definition used to construct an actual
     *                        {@link NamedFilterList} chain instance.
     * @see be.atbash.ee.security.octopus.filter.FilterChainResolver FilterChainResolver
     * @see be.atbash.ee.security.octopus.util.pattern.AntPathMatcher
     */
    // TODO Change/verify the example with perms in the javadoc
    protected void createChain(String chainName, String chainDefinition) {
        if (!StringUtils.hasText(chainName)) {
            throw new NullPointerException("chainName cannot be null or empty.");
        }
        if (!StringUtils.hasText(chainDefinition)) {
            throw new NullPointerException("chainDefinition cannot be null or empty.");
        }

        String realChainName = processChainName(chainName);
        if (log.isDebugEnabled()) {
            log.debug("Creating chain [" + realChainName + "] from String definition [" + chainDefinition + "]");
        }

        // Add the ExceptionFilter as first filter in the chain. Always!!
        addToChain(realChainName, EXCEPTION_FILTER_NAME, null);
        if (webConfiguration.isGlobalAuditActive()) {
            addToChain(realChainName, OctopusAuditFilter.AUDIT_FILTER_NAME, null);
        }

        for (GlobalFilterProvider globalFilterProvider : globalFilterProviders) {
            List<String> additionalFilters = globalFilterProvider.addFiltersTo(realChainName);

            for (String additionalFilter : additionalFilters) {
                String[] nameConfigPair = toNameConfigPair(additionalFilter);
                //now we have the filter name, path and (possibly null) path-specific config.  Let's apply them:
                addToChain(realChainName, nameConfigPair[0], nameConfigPair[1]);
            }

        }

        //parse the value by tokenizing it to get the resulting filter-specific config entries
        //
        //e.g. for a value of
        //
        //     "authc, roles[admin,user], perms[file:edit]"
        //
        // the resulting token array would equal
        //
        //     { "authc", "roles[admin,user]", "perms[file:edit]" }
        //
        String[] filterTokens = splitChainDefinition(chainDefinition);

        //each token is specific to each filter.
        //strip the name and extract any filter-specific config between brackets [ ]
        for (String token : filterTokens) {
            String[] nameConfigPair = toNameConfigPair(token);

            //now we have the filter name, path and (possibly null) path-specific config.  Let's apply them:
            addToChain(realChainName, nameConfigPair[0], nameConfigPair[1]);
        }

        NamedFilterList chain = ensureChain(realChainName);
        chain.listFinalFilterNames();
    }

    private String processChainName(String url) {
        String result = url;
        if (!url.startsWith("/")) {
            result = '/' + url;
        }
        return result;
    }

    /**
     * Splits the comma-delimited filter chain definition line into individual filter definition tokens.
     * <p/>
     * Example Input:
     * <pre>
     *     foo, bar[baz], blah[x, y]
     * </pre>
     * Resulting Output:
     * <pre>
     *     output[0] == foo
     *     output[1] == bar[baz]
     *     output[2] == blah[x, y]
     * </pre>
     * <p>
     * Specialized versions can override this method to support an extended or different version of the 'syntax'
     * used within the securedURLs.ini file to define the filters for each chain.
     *
     * @param chainDefinition the comma-delimited filter chain definition.
     * @return an array of filter definition tokens
     */
    protected String[] splitChainDefinition(String chainDefinition) {
        return StringUtils.split(chainDefinition, StringUtils.DEFAULT_DELIMITER_CHAR, '[', ']', true, true);
    }

    /**
     * Based on the given filter chain definition token (e.g. 'foo' or 'foo[bar, baz]'), this will return the token
     * as a name/value pair, removing any brackets as necessary.  Examples:
     * <table>
     * <tr>
     * <th>Input</th>
     * <th>Result</th>
     * </tr>
     * <tr>
     * <td>{@code foo}</td>
     * <td>returned[0] == {@code foo}<br/>returned[1] == {@code null}</td>
     * </tr>
     * <tr>
     * <td>{@code foo[bar, baz]}</td>
     * <td>returned[0] == {@code foo}<br/>returned[1] == {@code bar, baz}</td>
     * </tr>
     * </table>
     * <p>
     * Specialized versions can override this method to support an extended or different version of the 'syntax'
     * used within the securedURLs.ini file to define the filters for each chain.
     *
     * @param token the filter chain definition token
     * @return A name/value pair representing the filter name and a (possibly null) config value.
     * @throws ConfigurationException if the token cannot be parsed
     */
    protected String[] toNameConfigPair(String token) throws ConfigurationException {

        try {
            String[] pair = token.split("\\[", 2);
            String name = StringUtils.clean(pair[0]);

            if (name == null) {
                throw new ConfigurationException("Filter name not found for filter chain definition token: " + token);
            }
            String config = null;

            if (pair.length == 2) {
                config = StringUtils.clean(pair[1]);
                //if there was an open bracket, it assumed there is a closing bracket, so strip it too:
                config = config.substring(0, config.length() - 1);
                config = StringUtils.clean(config);

                //backwards compatibility prior to implementing SHIRO-205:
                //prior to SHIRO-205 being implemented, it was common for end-users to quote the config inside brackets
                //if that config required commas.  We need to strip those quotes to get to the interior quoted definition
                //to ensure any existing quoted definitions still function for end users:
                if (config != null && config.startsWith("\"") && config.endsWith("\"")) {
                    String stripped = config.substring(1, config.length() - 1);
                    stripped = StringUtils.clean(stripped);

                    //if the stripped value does not have any internal quotes, we can assume that the entire config was
                    //quoted and we can use the stripped value.
                    if (stripped != null && stripped.indexOf('"') == -1) {
                        config = stripped;
                    }
                    //else:
                    //the remaining config does have internal quotes, so we need to assume that each comma delimited
                    //pair might be quoted, in which case we need the leading and trailing quotes that we stripped
                    //So we ignore the stripped value.
                }
            }

            return new String[]{name, config};

        } catch (Exception e) {
            String msg = "Unable to parse filter chain definition token: " + token;
            throw new ConfigurationException(msg, e);
        }
    }

    /**
     * Adds (appends) a filter to the filter chain identified by the given {@code chainName}.  If there is no chain
     * with the given name, a new one is created and the filter will be the first in the chain.
     * <p/>
     * Note that the chainSpecificFilterConfig argument expects the associated filter to be an instance of
     * a {@link be.atbash.ee.security.octopus.filter.PathMatchingFilter PathMatchingFilter} to accept per-chain configuration.
     * If it is not, a {@link ConfigurationException} will be thrown.
     *
     * @param chainName                 the name of the chain where the filter will be appended.
     * @param filterName                the name of the {@link #addFilter registered} filter to add to the chain.
     * @param chainSpecificFilterConfig the filter-specific configuration that should be applied for only the specified
     *                                  filter chain. Null is allowed.
     * @throws ConfigurationException if there is not a {@link #addFilter(String, AbstractFilter) registered}
     *                                filter under the given {@code filterName}.
     */
    protected void addToChain(String chainName, String filterName, String chainSpecificFilterConfig) {

        // TODO Support a flag for 'validating' filter chains.
        // Like did we use the correct order?

        if (!StringUtils.hasText(chainName)) {
            throw new IllegalArgumentException("(E0010) Error : chainName cannot be null or empty.");
        }
        AdviceFilter filter = getFilter(filterName);
        if (filter == null) {
            throw new ConfigurationException(
                    String.format("(E0011) Error : There is no filter with name '%s' to apply to chain [%s]" +
                            " in the pool of available Filters.  Ensure a filter with that name/path has first been registered with the addFilter method(s).", filterName, chainName));
        }

        applyChainConfig(chainName, filter, chainSpecificFilterConfig);

        NamedFilterList chain = ensureChain(chainName);
        chain.add(filter);
    }

    /**
     * Apply the filter config for that chain to the Filter.
     *
     * @param chainName                 The chain name for which the filter config is to be used.
     * @param filter                    The filter for which the config is specified
     * @param chainSpecificFilterConfig The filter config, the 'syntax' is filter dependent.
     * @throws ConfigurationException When chainSpecificFilterConfig is specified but filter itself doesn't accept it.
     */
    private void applyChainConfig(String chainName, AdviceFilter filter, String chainSpecificFilterConfig) {
        if (log.isDebugEnabled()) {
            log.debug("Attempting to apply path [" + chainName + "] to filter [" + filter + "] " +
                    "with config [" + chainSpecificFilterConfig + "]");
        }
        if (filter instanceof PathMatchingFilter) {
            ((PathMatchingFilter) filter).processPathConfig(chainName, chainSpecificFilterConfig);
        } else {
            if (StringUtils.hasText(chainSpecificFilterConfig)) {
                //they specified a filter configuration, but the Filter doesn't implement PathConfigProcessor
                //this is an erroneous config:
                String msg = String.format("(E0012) Error : chainSpecificFilterConfig was specified for filter '%s', but this " +
                        "Filter not an 'instanceof' %s.  This is required if the filter is to accept " +
                        "chain-specific configuration.", filter.getClass().getName(), PathMatchingFilter.class.getName());
                throw new ConfigurationException(msg);
            }
        }
    }

    /**
     * Retrieves the NamedFilterList linked to the chainName. If is does not exist yet, it creates
     * a new chain with an empty list of Filters.
     *
     * @param chainName
     * @return
     */
    private NamedFilterList ensureChain(String chainName) {
        NamedFilterList chain = getChain(chainName);
        if (chain == null) {
            chain = new NamedFilterList(chainName);
            filterChains.put(chainName, chain);
        }
        return chain;
    }

    /**
     * Returns the filter chain identified by the specified {@code chainName} or {@code null} if there is no chain with
     * that name.
     *
     * @param chainName the name identifying the filter chain.
     * @return the filter chain identified by the specified {@code chainName} or {@code null} if there is no chain with
     * that name.
     */
    public NamedFilterList getChain(String chainName) {
        return filterChains.get(chainName);
    }

    /**
     * Returns {@code true} if one or more configured chains are available, {@code false} if none are configured.
     *
     * @return {@code true} if one or more configured chains are available, {@code false} if none are configured.
     */
    public boolean hasChains() {
        return !CollectionUtils.isEmpty(filterChains);
    }

    /**
     * Returns the names of all configured chains or an empty {@code Set} if no chains have been configured.
     *
     * @return the names of all configured chains or an empty {@code Set} if no chains have been configured.
     */
    public Set<String> getChainNames() {
        //noinspection unchecked
        return filterChains != null ? filterChains.keySet() : Collections.EMPTY_SET;
    }

    /**
     * Proxies the specified {@code original} FilterChain with the named chain.  The returned
     * {@code FilterChain} instance will first execute the configured named chain and then lastly invoke the given
     * {@code original} chain.
     *
     * @param original  the original FilterChain to proxy
     * @param chainName the name of the internal configured filter chain that should 'sit in front' of the specified
     *                  original chain.
     * @return a {@code FilterChain} instance that will execute the named chain and then finally the
     * specified {@code original} FilterChain instance.
     * @throws IllegalArgumentException if there is no configured chain with the given {@code chainName}.
     */
    public FilterChain proxy(FilterChain original, String chainName) {
        NamedFilterList configured = getChain(chainName);
        if (configured == null) {
            String msg = "There is no configured chain under the name/key [" + chainName + "].";
            throw new IllegalArgumentException(msg);
        }
        return configured.proxy(original);
    }

}

