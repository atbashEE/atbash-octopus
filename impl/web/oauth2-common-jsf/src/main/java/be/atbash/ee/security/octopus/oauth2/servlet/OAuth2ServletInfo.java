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
package be.atbash.ee.security.octopus.oauth2.servlet;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authc.event.LogoutEvent;
import be.atbash.ee.security.octopus.oauth2.config.ProviderSelection;
import be.atbash.ee.security.octopus.oauth2.config.UserProviderSelection;
import be.atbash.ee.security.octopus.oauth2.config.jsf.OAuth2JSFConfiguration;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2Provider;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderMetaData;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderMetaDataControl;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.SavedRequest;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.util.PublicAPI;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.annotation.PostConstruct;
import javax.enterprise.context.SessionScoped;
import javax.enterprise.event.Observes;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.inject.Inject;
import javax.inject.Named;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 *
 */
@SessionScoped
@Named("oauth2ServletInfo")
@PublicAPI
public class OAuth2ServletInfo implements UserProviderSelection, Serializable {

    @Inject
    private OAuth2ProviderMetaDataControl oAuth2ProviderMetaDataControl;

    @Inject
    private OAuth2JSFConfiguration oAuth2Configuration;

    @Inject
    private ProviderSelection providerSelection;

    private String userProviderSelection;

    private List<SelectItem> providerSelectionItems;
    private List<OAuth2ProviderMetaData> providerInfos;

    @PostConstruct
    public void init() {

        providerInfos = oAuth2ProviderMetaDataControl.getProviderInfos();

        providerSelectionItems = new ArrayList<>();
        for (OAuth2Provider providerInfo : providerInfos) {
            providerSelectionItems.add(new SelectItem(providerInfo.getName(), providerInfo.getName()));
        }

    }

    public String getServletPath() {
        String result = null;
        if (StringUtils.isEmpty(userProviderSelection)) {
            if (providerInfos.size() > 1) {
                result = oAuth2Configuration.getOAuth2ProviderSelectionPage();
            } else {
                result = providerInfos.get(0).getServletPath();
            }
        } else {
            Iterator<OAuth2ProviderMetaData> iter = providerInfos.iterator();
            while (result == null && iter.hasNext()) {
                OAuth2ProviderMetaData providerInfo = iter.next();
                if (providerInfo.getName().equals(userProviderSelection)) {
                    result = providerInfo.getServletPath();
                }
            }
        }
        // FIXME Verify if this is correct message and correct way to handle the situation
        if (StringUtils.isEmpty(result)) {
            throw new AtbashIllegalActionException(String.format("Provider selection '%s' not found. Wrong value passed OAuth2ServletInfo#authenticateWith()?", userProviderSelection));
        }
        return result;
    }

    public void authenticateWith(String userProviderSelection) {
        verifyUserProviderSelection(userProviderSelection);
        this.userProviderSelection = userProviderSelection;
        providerSelection.setProviderSelection(userProviderSelection);
        ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
        WebSubject subject = SecurityUtils.getSubject();
        SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(subject);

        try {
            externalContext
                    .redirect(savedRequest != null ? savedRequest.getRequestUrl() : getRootUrl(externalContext));
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }

    }

    private void verifyUserProviderSelection(String userProviderSelection) {
        boolean found = false;
        for (OAuth2Provider providerInfo : providerInfos) {
            if (providerInfo.getName().equals(userProviderSelection)) {
                found = true;
            }
        }
        if (!found) {
            throw new AtbashIllegalActionException(String.format("(OCT-DEV-???) Provider name not found %s. Must be one of %s", userProviderSelection, getProviderNames()));
        }
    }

    private String getRootUrl(ExternalContext externalContext) {
        return externalContext.getRequestContextPath();
    }

    @Override
    public String getSelection() {
        return userProviderSelection;
    }

    public List<SelectItem> getProviderSelectItems() {
        return providerSelectionItems;
    }

    public List<String> getProviders() {
        List<String> result = new ArrayList<>();
        for (SelectItem selectItem : providerSelectionItems) {
            result.add(selectItem.getLabel());
        }
        return result;
    }

    private String getProviderNames() {
        // TODO Duplicate with OAuth2ProviderMetaDataControl
        StringBuilder result = new StringBuilder();
        for (OAuth2Provider providerInfo : providerInfos) {
            if (result.length() > 1) {
                result.append(" - ");
            }
            result.append(providerInfo.getName());
        }
        return result.toString();
    }

    public void onLogout(@Observes LogoutEvent logoutEvent) {
        userProviderSelection = null;
    }
}
