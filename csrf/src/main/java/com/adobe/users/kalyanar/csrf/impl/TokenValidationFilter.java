package com.adobe.users.kalyanar.csrf.impl;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.apache.sling.api.SlingHttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.adobe.users.kalyanar.csrf.CSRFGuardConfiguration;
import com.adobe.users.kalyanar.csrf.JWTBuilder;

/**
 * This implementation will be used until the granite csrf guard bundle is
 * delivered as part of the AEM
 * 
 * @author kalyanar
 * 
 */
@Component(metatype = false, description = "Request filter checking the CSRF token of modification requests.", label = "Nedbank  CSRF Token Validation Filter")
@Service
@Properties({
		@Property(name = "sling.filter.scope", value = { "request" }, propertyPrivate = true),
		@Property(name = "service.ranking", intValue = Integer.MIN_VALUE, propertyPrivate = true) })
public class TokenValidationFilter implements Filter {
	private final Logger logger = LoggerFactory
			.getLogger(TokenValidationFilter.class);

	@Reference
	private JWTBuilder jwtbuilder;

	@Reference
	private CSRFGuardConfiguration csrfConfig;

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {

	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		final HttpServletRequest httpRequest = (HttpServletRequest) request;
		if (this.isFilteredMethod(httpRequest)) {
			String uri = httpRequest.getRequestURI();
			if(request instanceof SlingHttpServletRequest){
				SlingHttpServletRequest slingRequest = (SlingHttpServletRequest) request;
				uri = slingRequest.getRequestPathInfo().getResourcePath();
			}
			if (isProtectedPage(uri)&&!this.isValidRequest(httpRequest)) {
				final HttpServletResponse httpResponse = (HttpServletResponse) response;
				// we use 403
				logger.info("doFilter: the provided CSRF token is invalid");
				httpResponse.sendError(403);
				return;
			}

		}
		chain.doFilter(request, response);
	}

	@Override
	public void destroy() {
		// TODO Auto-generated method stub

	}

	private boolean isValidRequest(final HttpServletRequest request) {
		String csrf = request.getParameter(csrfConfig.getTokenParamName());
		if (StringUtils.isBlank(csrf)) {
			csrf = request.getHeader(csrfConfig.getTokenParamName());
			if (StringUtils.isBlank(csrf)) {
				logger.info("isValidRequest: empty CSRF token - rejecting");
				return false;
			}
		}

		return jwtbuilder.verifyToken(csrf);
	}

	private boolean isFilteredMethod(final HttpServletRequest req) {
		final String method = req.getMethod();
		if (csrfConfig.getFilterMethodsSet() != null) {
			return csrfConfig.getFilterMethodsSet().contains(method);
		}
		return false;
	}
	public boolean isProtectedPage(String uri) {
		boolean retVal = true;
		for (String protectedPage : csrfConfig.getProtectedPages()) {
			if(uri.startsWith(protectedPage)){
				retVal = true;
			}
		}
		
		for (String unprotectedPage : csrfConfig.getUnprotectedPages()) {
			if(!StringUtils.isBlank(unprotectedPage)&&uri.startsWith(unprotectedPage)){
				return false;
			}
		}
		return retVal;
	}
}
