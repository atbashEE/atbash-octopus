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
package be.atbash.ee.oauth2.sdk.http;


import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.*;


/**
 * Mock servlet request.
 */
// FIXME Mockito?
public class MockServletRequest implements HttpServletRequest {


	private String method;


	private Map<String, List<String>> headers = new LinkedHashMap<>();

	
	private Map<String, String[]> parameters = new LinkedHashMap<>();
	
	
	private Map<String, Object> attributes = new LinkedHashMap<>();

	
	private String addr;
	
	
	private String remoteAddr;


	private int localPort;


	private String requestURI;


	private String queryString;


	private String entityBody;


	public void setEntityBody(String entityBody) {

		this.entityBody = entityBody;
	}


	@Override
	public String getAuthType() {
		return null;
	}


	@Override
	public Cookie[] getCookies() {
		return new Cookie[0];
	}


	@Override
	public long getDateHeader(String s) {
		return 0;
	}


	public void setHeader(String header, String... value) {
		
		headers.put(header.toLowerCase(), Arrays.asList(value));
	}


	@Override
	public String getHeader(String s) {

		return MultivaluedMapUtils.getFirstValue(headers, s.toLowerCase());
	}


	@Override
	public Enumeration<String> getHeaders(String s) {
		
		List<String> headerValues = headers.get(s);
		
		if (s == null)
			return new Vector<String>().elements(); // empty
		
		return new Vector<>(headerValues).elements();
	}


	@Override
	public Enumeration<String> getHeaderNames() {

		return new Vector(headers.keySet()).elements();
	}


	@Override
	public int getIntHeader(String s) {
		return 0;
	}


	public void setMethod(String method) {

		this.method = method;
	}


	@Override
	public String getMethod() {

		return method;
	}


	@Override
	public String getPathInfo() {
		return null;
	}


	@Override
	public String getPathTranslated() {
		return null;
	}


	@Override
	public String getContextPath() {
		return null;
	}


	public void setQueryString(String queryString) {

		this.queryString = queryString;
	}


	@Override
	public String getQueryString() {

		return queryString;
	}


	@Override
	public String getRemoteUser() {
		return null;
	}


	@Override
	public boolean isUserInRole(String s) {
		return false;
	}


	@Override
	public Principal getUserPrincipal() {
		return null;
	}


	@Override
	public String getRequestedSessionId() {
		return null;
	}


	public void setRequestURI(String requestURI) {

		this.requestURI = requestURI;
	}


	@Override
	public String getRequestURI() {

		return requestURI;
	}


	@Override
	public StringBuffer getRequestURL() {
		return null;
	}


	@Override
	public String getServletPath() {
		return null;
	}


	@Override
	public HttpSession getSession(boolean b) {
		return null;
	}


	@Override
	public HttpSession getSession() {
		return null;
	}


	@Override
	public boolean isRequestedSessionIdValid() {
		return false;
	}


	@Override
	public boolean isRequestedSessionIdFromCookie() {
		return false;
	}


	@Override
	public boolean isRequestedSessionIdFromURL() {
		return false;
	}


	@Override
	public boolean isRequestedSessionIdFromUrl() {
		return false;
	}


	@Override
	public boolean authenticate(HttpServletResponse httpServletResponse) throws IOException, ServletException {
		return false;
	}


	@Override
	public void login(String s, String s1) throws ServletException {

	}


	@Override
	public void logout() throws ServletException {

	}


	@Override
	public Collection<Part> getParts() throws IOException, ServletException {
		return null;
	}


	@Override
	public Part getPart(String s) throws IOException, ServletException {
		return null;
	}


	@Override
	public Object getAttribute(String s) {
		
		return attributes.get(s);
	}


	@Override
	public Enumeration<String> getAttributeNames() {
		return null;
	}


	@Override
	public String getCharacterEncoding() {
		return null;
	}


	@Override
	public void setCharacterEncoding(String s) throws UnsupportedEncodingException {

	}


	@Override
	public int getContentLength() {

		return 0;
	}


	@Override
	public String getContentType() {

		return MultivaluedMapUtils.getFirstValue(headers, "content-type");
	}


	@Override
	public ServletInputStream getInputStream() throws IOException {
		return null;
	}


	@Override
	public String getParameter(String s) {
	    String[] values = parameters.get(s);
		return values != null ? values[0] : null;
	}


	@Override
	public Enumeration<String> getParameterNames() {
		return Collections.enumeration(parameters.keySet());
	}


	@Override
	public String[] getParameterValues(String s) {
		return parameters.get(s);
	}


	@Override
	public Map<String, String[]> getParameterMap() {
		return parameters;
	}

	public void setParameter(String key, String... values) {
	    parameters.put(key, values);
	}

	@Override
	public String getProtocol() {
		return null;
	}


	@Override
	public String getScheme() {
		return null;
	}


	@Override
	public String getServerName() {
		return null;
	}


	@Override
	public int getServerPort() {
		return 0;
	}


	@Override
	public BufferedReader getReader() throws IOException {

		return new BufferedReader(new StringReader(entityBody));
	}


	public void setRemoteAddr(String remoteAddr) {
		
		this.remoteAddr = remoteAddr;
	}


	@Override
	public String getRemoteAddr() {
		return remoteAddr;
	}


	@Override
	public String getRemoteHost() {
		return null;
	}


	@Override
	public void setAttribute(String s, Object o) {

		attributes.put(s, o);
	}


	@Override
	public void removeAttribute(String s) {

	}


	@Override
	public Locale getLocale() {
		return null;
	}


	@Override
	public Enumeration<Locale> getLocales() {
		return null;
	}


	@Override
	public boolean isSecure() {
		return false;
	}


	@Override
	public RequestDispatcher getRequestDispatcher(String s) {
		return null;
	}


	@Override
	public String getRealPath(String s) {
		return null;
	}


	@Override
	public int getRemotePort() {
		return 0;
	}


	@Override
	public String getLocalName() {
		return null;
	}


	public void setLocalAddr(String addr) {

		this.addr = addr;
	}


	@Override
	public String getLocalAddr() {

		return addr;
	}


	public void setLocalPort(int localPort) {

		this.localPort = localPort;
	}


	@Override
	public int getLocalPort() {

		return localPort;
	}


	@Override
	public ServletContext getServletContext() {
		return null;
	}


	@Override
	public AsyncContext startAsync() throws IllegalStateException {
		return null;
	}


	@Override
	public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws IllegalStateException {
		return null;
	}


	@Override
	public boolean isAsyncStarted() {
		return false;
	}


	@Override
	public boolean isAsyncSupported() {
		return false;
	}


	@Override
	public AsyncContext getAsyncContext() {
		return null;
	}


	@Override
	public DispatcherType getDispatcherType() {
		return null;
	}

	@Override
	public String changeSessionId() {
		return null;
	}

	@Override
	public <T extends HttpUpgradeHandler> T upgrade(Class<T> handlerClass) throws IOException, ServletException {
		return null;
	}

	@Override
	public long getContentLengthLong() {
		return 0;
	}
}
