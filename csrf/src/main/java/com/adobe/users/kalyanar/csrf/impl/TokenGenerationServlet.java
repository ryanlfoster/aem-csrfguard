package com.adobe.users.kalyanar.csrf.impl;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferencePolicy;
import org.apache.felix.scr.annotations.sling.SlingServlet;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingSafeMethodsServlet;
import org.apache.sling.commons.json.JSONException;
import org.apache.sling.commons.json.io.JSONWriter;
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
@SlingServlet(paths = { "/bin/aem/csrfguard/generatetoken" }, extensions = { "json" }, metatype = false, description = "Servlet that return the CSRF token for a given user.", label = "aem CSRF Token Generation Servlet",generateComponent= true)
public class TokenGenerationServlet extends SlingSafeMethodsServlet {
	private final Logger logger = LoggerFactory
			.getLogger(TokenGenerationServlet.class);

	@Reference
	private JWTBuilder jwtbuilder;

	@Reference(policy=ReferencePolicy.STATIC)
	private CSRFGuardConfiguration csrfConfig;
	

	@Override
	protected void doGet(SlingHttpServletRequest request,
			SlingHttpServletResponse response) throws ServletException,
			IOException {
		String token;
		try {
			token = jwtbuilder.generateJsonWebToken(request.getRemoteUser());
			response.setContentType("application/json");
			response.setCharacterEncoding("utf8");
			response.setHeader("Cache-Control", "no-cache");
			response.setStatus(HttpServletResponse.SC_OK);

			JSONWriter writer = new JSONWriter(response.getWriter());
			writer.object();
			writer.key(csrfConfig.getTokenParamName()).value(token);
			writer.endObject();
		}catch (JSONException e) {
			logger.error("doGet: failed to generate CSRF token", e);
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}
	}
}
