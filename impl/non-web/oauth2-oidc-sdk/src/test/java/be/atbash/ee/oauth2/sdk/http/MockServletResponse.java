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


import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.*;


/**
 * Mock servlet response.
 */
// FIXME Mockito?
class MockServletResponse implements HttpServletResponse {


	private int status;


	private Map<String, String> headers = new HashMap<>();


	private ByteArrayOutputStream content = new ByteArrayOutputStream();


	@Override
	public void addCookie(Cookie cookie) {

	}


	@Override
	public boolean containsHeader(String s) {
		return false;
	}


	@Override
	public String encodeURL(String s) {
		return null;
	}


	@Override
	public String encodeRedirectURL(String s) {
		return null;
	}


	@Override
	public String encodeUrl(String s) {
		return null;
	}


	@Override
	public String encodeRedirectUrl(String s) {
		return null;
	}


	@Override
	public void sendError(int i, String s) throws IOException {

	}


	@Override
	public void sendError(int i) throws IOException {

	}


	@Override
	public void sendRedirect(String s) throws IOException {

	}


	@Override
	public void setDateHeader(String s, long l) {

	}


	@Override
	public void addDateHeader(String s, long l) {

	}


	@Override
	public void setHeader(String s, String s2) {

		headers.put(s.toLowerCase(), s2);
	}


	@Override
	public void addHeader(String s, String s2) {

		headers.put(s.toLowerCase(), s2);
	}


	@Override
	public void setIntHeader(String s, int i) {

		headers.put(s, Integer.toString(i));
	}


	@Override
	public void addIntHeader(String s, int i) {

		headers.put(s, Integer.toString(i));
	}


	@Override
	public void setStatus(int i) {

		status = i;
	}


	@Override
	public void setStatus(int i, String s) {

		status = i;
	}


	@Override
	public int getStatus() {

		return status;
	}


	@Override
	public String getHeader(String s) {

		return headers.get(s.toLowerCase());
	}


	@Override
	public Collection<String> getHeaders(String s) {

		Collection<String> h = new ArrayList<>(1);

		String value = headers.get(s);

		if (value != null)
			h.add(value);

		return h;
	}


	@Override
	public Collection<String> getHeaderNames() {
		return null;
	}


	@Override
	public String getCharacterEncoding() {
		return null;
	}


	@Override
	public String getContentType() {

		return headers.get("Content-Type");
	}


	@Override
	public ServletOutputStream getOutputStream() throws IOException {
		return null;
	}


	@Override
	public PrintWriter getWriter() throws IOException {

		return new PrintWriter(content);
	}


	public String getContent() throws UnsupportedEncodingException {

		return content.toString("UTF-8");
	}


	@Override
	public void setCharacterEncoding(String s) {

	}


	@Override
	public void setContentLength(int i) {

	}


	@Override
	public void setContentType(String s) {

		headers.put("Content-Type", s);
	}


	@Override
	public void setBufferSize(int i) {

	}


	@Override
	public int getBufferSize() {
		return 0;
	}


	@Override
	public void flushBuffer() throws IOException {

	}


	@Override
	public void resetBuffer() {

	}


	@Override
	public boolean isCommitted() {
		return false;
	}


	@Override
	public void reset() {

	}


	@Override
	public void setLocale(Locale locale) {

	}


	@Override
	public Locale getLocale() {
		return null;
	}

	@Override
	public void setContentLengthLong(long len) {

	}
}
