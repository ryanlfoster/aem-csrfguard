package com.adobe.users.kalyanar.csrf.impl;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.PropertyUnbounded;
import org.apache.felix.scr.annotations.Service;
import org.apache.sling.commons.osgi.PropertiesUtil;
import org.osgi.service.component.ComponentContext;

import com.adobe.users.kalyanar.csrf.CSRFGuardConfiguration;

@Component(name=“AEM CSRF Guard Configuration",description = “AEM CSRF Guard configuration",metatype = true, policy=ConfigurationPolicy.REQUIRE)
@Service
public class CSRFGuardConfigurationImpl implements CSRFGuardConfiguration {
	 
	 private static final long DEFAULT_TOKEN_EXPIRATION_TIME = 600;
	 private static final String DEFAULT_TOKEN_NAME = “aem_csrf_token";
	 private static final String DEFAULT_TOKEN_PARAM_NAME = "aem_csrf_token";
	 private static final String DEFAULT_JAVASCRIPT_TEMPLATE_FILE = "csrfguard.js";

	 private static final String DEFAULT_CLAIMSET_KEY = "csrfscopeeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

	    @Property(longValue = DEFAULT_TOKEN_EXPIRATION_TIME, label = "CSRF Token Expires In", description = "The lifetime in seconds of the csrf token"
	            )
	    private static final String PROP_TOKEN_EXPIRATION_TIME = "token.expiration.time";
	    
	    @Property(value = DEFAULT_TOKEN_NAME, label = "CSRF Token Name", description = "The csrf guard token name"
	            )
	    private static final String PROP_TOKEN_NAME = "token.name";
	    
	    @Property(value = DEFAULT_TOKEN_PARAM_NAME, label = "CSRF Token parameter(request or header) Name", description = "The csrf guard token request or header parameter  name"
	            )
	    private static final String PROP_TOKEN_PARAM_NAME = "token.param.name";
	    
	    @Property(value = DEFAULT_CLAIMSET_KEY, label = "JWT claimset key", description = "JCT claimset key name"
	            )
	    private static final String PROP_CLAIMSET_KEY = "scope";
	    
	    @Property(value = DEFAULT_JAVASCRIPT_TEMPLATE_FILE, label = "CSRF javascript template file", description = "The javascript template file",propertyPrivate=true
	            )
	    private static final String PROP_JAVASCRIPT_TEMPLATE_FILE = "csrf.javascript.template.file";
	    
	    
	    /** Filtered methods property */
	    @Property(label="Filter Methods", 
	            description="These methods are filtered by the filter.",
	            unbounded=PropertyUnbounded.ARRAY, value={"POST", "DELETE"})
	    private static final String PROP_METHODS = "filter.methods";
   	 
	    @Property(unbounded = PropertyUnbounded.ARRAY , value = {"/bin/aem/csrfguard/generatetoken"})
	    private static final String PROP_UNPROTECTED = "unprotected.paths";
	    
	    @Property(unbounded = PropertyUnbounded.ARRAY )
	    private static final String PROP_PROTECTED = "protected.paths";
	    
	    private Set<String> filterMethodsSet;
	    private long csrfTokenExpiresIn;
	    private String tokenName;
	    private String javascriptTemplate;
	    private String tokenParamName;
	    private String claimsetKey;
	    private Set<String> protectedPages;
	    private Set<String> unprotectedPages;
	    public Set<String> getUnprotectedPages() {
	        return unprotectedPages;
	    }
	    
	    public Set<String> getProtectedPages() {
	        return protectedPages;
	    }
	    public String getClaimsetKey() {
			return claimsetKey;
		}


		public long getCsrfTokenExpiresIn() {
			return csrfTokenExpiresIn;
		}


		public String getTokenName() {
			return tokenName;
		}
		public String getTokenParamName() {
			return tokenParamName;
		}

		public Set<String> getFilterMethodsSet() {
			return filterMethodsSet;
		}

		@Activate
	    @Modified
	    private void activate(ComponentContext context,Map<String, Object> props) { 
	        csrfTokenExpiresIn = PropertiesUtil.toLong(props.get(PROP_TOKEN_EXPIRATION_TIME), DEFAULT_TOKEN_EXPIRATION_TIME);
	        tokenName = PropertiesUtil.toString(props.get(PROP_TOKEN_NAME), DEFAULT_TOKEN_NAME);
	        tokenParamName = PropertiesUtil.toString(props.get(PROP_TOKEN_PARAM_NAME), DEFAULT_TOKEN_PARAM_NAME);
	        claimsetKey = PropertiesUtil.toString(props.get(PROP_CLAIMSET_KEY), DEFAULT_CLAIMSET_KEY);
	        String[] filterMethods = PropertiesUtil.toStringArray(props.get(PROP_METHODS),new String[0]);
	       String jsTemplateFileName = PropertiesUtil.toString(props.get(PROP_JAVASCRIPT_TEMPLATE_FILE), DEFAULT_JAVASCRIPT_TEMPLATE_FILE);
	       Class cls = getClass();
	      URL url= context.getBundleContext().getBundle().getResource(jsTemplateFileName);
			InputStream is =null;
			try {
				is = url.openStream();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

	       this.javascriptTemplate = readInputStreamContent(is);
	       for(int i=0; i<filterMethods.length; i++) {
	            filterMethods[i] = filterMethods[i].toUpperCase();
	        }   
	        filterMethodsSet = toStringSet(filterMethods);
	        this.protectedPages = toStringSet(props.get(PROP_PROTECTED));
	        this.unprotectedPages = toStringSet(props.get(PROP_UNPROTECTED));
		}

	    private Set<String> toStringSet(Object object) {
	        String[] temp = PropertiesUtil.toStringArray(object);
	        if (temp == null) {
	            return Collections.emptySet();
	        } else {
	            return new HashSet<String>(Arrays.asList(temp));
	        }
	    }

		@Override
		public String getJavascriptTemplate() {
			return this.javascriptTemplate;
		}
		public String readInputStreamContent(InputStream is) {
			StringBuilder sb = new StringBuilder();

			try {
				int i;

				while ((i = is.read()) > 0) {
					sb.append((char) i);
				}
			} catch (IOException ioe) {
				throw new RuntimeException(ioe);
			}

			return sb.toString();
		}
}
