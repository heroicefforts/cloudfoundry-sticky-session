package com.pyclid.web.filter;


import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.servlet.http.HttpSession;


public class DebugFilter implements Filter {
	private int id = 0;
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		//empty
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {
		StringBuilder buf = new StringBuilder();
		boolean sessionExists = false;
		String value = null;

		if(request instanceof HttpServletRequest) {
			HttpServletRequest hreq = (HttpServletRequest) request;
			HttpSession session = hreq.getSession(false);
			sessionExists = session != null;
			if(session != null)
				value = (String) session.getAttribute("aggravating");
			else {
				session = hreq.getSession(true);
				session.setAttribute("aggravating", "happy");
			}
			
			buf.append(request.getScheme()).append("://").append(request.getLocalAddr()).append(":").append(request.getLocalPort())
				.append(hreq.getRequestURI()).append("\n");
			buf.append("Origin:  ").append(hreq.getRemoteAddr()).append(':').append(hreq.getRemotePort()).append('\n');
		
			Cookie[] cookiesIn = hreq.getCookies();
			if(cookiesIn != null) {
				buf.append("Request cookies:  \n");
				for(Cookie c : cookiesIn) {
					appendCookie(buf, c);
				}
			}
			else
				buf.append("No request cookies.\n");
		}
		
		if(response instanceof HttpServletResponse) {
			final HeaderTrack resp = new HeaderTrack((HttpServletResponse) response);
			chain.doFilter(request, resp);
			
			if(resp.headers.isEmpty())
				buf.append("No response headers.\n");
			else {
				buf.append("Response headers:\n");
				for(String header : resp.headers)
					buf.append("  ").append(header).append('\n');
			}

			if(resp.cookies.isEmpty())
				buf.append("No new app defined cookies.\n");
			else {
				buf.append("Application cookies:\n");
				for(Cookie cookie : resp.cookies) {
					appendCookie(buf, cookie);
				}
			}
		}
		else
			chain.doFilter(request, response);
		
		buf.append("VCAP_APPLICATION:  ").append(System.getenv("VCAP_APPLICATION"))
				.append(", VCAP_PORT:  ").append(System.getenv("PORT")).append("\n");
		
		buf.append("Session exists:  ").append(sessionExists).append(", Session value:").append(value);
		
		//logger.info("Processed request({}):  {}", id, buf);
		System.out.println("One liner(" + id++ + "):  " + buf.toString().replaceAll("\n", "    "));
	}

	private static final void appendCookie(StringBuilder buf, Cookie cookie) {
		buf.append("  ")
			.append("name:").append(cookie.getName()).append(", ")
			.append("value:").append(cookie.getValue()).append(", ")
			.append("domain:").append(cookie.getDomain()).append(", ")
			.append("path:").append(cookie.getPath()).append(", ")
			.append("max_age:").append(cookie.getMaxAge()).append(", ")
			.append("version:").append(cookie.getVersion()).append(", ")
			.append("secure:").append(cookie.getSecure())
			.append('\n');
	}

	@Override
	public void destroy() {
		
	}

	private class HeaderTrack extends HttpServletResponseWrapper {
		private ArrayList<String> headers = new ArrayList<String>();
		private ArrayList<Cookie> cookies = new ArrayList<Cookie>();
		
		
		public HeaderTrack(HttpServletResponse response) {
			super(response);
		}

		@Override
		public void setHeader(java.lang.String name, java.lang.String value) {
			super.setHeader(name, value);
			headers.add(name + "::" + value);
		}
		
		@Override
		public void addHeader(java.lang.String name, java.lang.String value) {
			super.addHeader(name, value);
			headers.add(name + "::" + value);
		}
		
		@Override
		public void addCookie(Cookie cookie) {
			super.addCookie(cookie);
			cookies.add(cookie);
		}
		
	}
	
}
