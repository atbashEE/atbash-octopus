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
package be.atbash.ee.security.octopus.view.interceptor;

import be.atbash.ee.jsf.jerry.interceptor.AbstractRendererInterceptor;
import be.atbash.ee.jsf.jerry.interceptor.exception.SkipAfterInterceptorsException;
import be.atbash.ee.jsf.jerry.interceptor.exception.SkipBeforeInterceptorsException;
import be.atbash.ee.jsf.jerry.interceptor.exception.SkipRendererDelegationException;

import javax.enterprise.context.ApplicationScoped;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.render.Renderer;
import javax.inject.Inject;
import java.io.IOException;

/**
 *
 */
@ApplicationScoped
public class PermissionInterceptor extends AbstractRendererInterceptor {

    @Inject
    private SecuredRuntimeManager securedRuntimeManager;

    @Override
    public void beforeEncodeBegin(final FacesContext facesContext, final UIComponent uiComponent,
                                  final Renderer renderer) throws IOException, SkipBeforeInterceptorsException,
            SkipRendererDelegationException {

        securedRuntimeManager.checkRendererStatus(uiComponent);
    }

    @Override
    public void afterEncodeEnd(final FacesContext facesContext, final UIComponent uiComponent,
                               final Renderer renderer) throws IOException, SkipAfterInterceptorsException {
        // The afterEncodeEnd is not called for not rendered components.  So we catch here the afterEncodeEnd of the
        // parent.
        securedRuntimeManager.resetRenderedStatus(uiComponent);
    }

}
