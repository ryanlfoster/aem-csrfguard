package com.adobe.users.kalyanar.csrf.impl;

import java.io.IOException;
import java.io.InputStream;

import javax.servlet.ServletException;

import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.ReferencePolicy;
import org.apache.felix.scr.annotations.sling.SlingServlet;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingSafeMethodsServlet;

import com.adobe.users.kalyanar.csrf.CSRFGuardConfiguration;

@SlingServlet(paths = { "/bin/nedbank/csrfguard" }, extensions = { "js" }, metatype = false, description = "Servlet that return the CSRF token for a given user.", label = "Nedbank CSRF Token Generation Servlet",generateComponent= true)
public class JavascriptServlet extends SlingSafeMethodsServlet {
	
	@Reference(policy = ReferencePolicy.DYNAMIC,cardinality=ReferenceCardinality.OPTIONAL_UNARY)
	private volatile  CSRFGuardConfiguration csrfConfig;
	@Override
	protected void doGet(SlingHttpServletRequest request,
			SlingHttpServletResponse response) throws ServletException,
			IOException {
		response.setContentType("application/javascript");
	if(csrfConfig==null){
		response.getWriter().write("//CSRF Guard is disabled");
		return;
	}
	String jsTemplateCode = csrfConfig.getJavascriptTemplate();
	response.getWriter().write(jsTemplateCode);
	}

	
}
