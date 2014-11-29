package com.adobe.users.kalyanar.csrf;

import java.util.Set;
/**
 * This configuration will allow us to configure the token names of csrf guard.
 * This approach used jwt(https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31)
 * You can set token name, claimset name and token expiry time. As of now, the configurations for adding
 * the token to the dom via javascript are not configurable.
 * We can also add some pages that have to be protected via this and some pages that need not be protected at all
 * 
 * @author kalyanar
 *
 */
public interface CSRFGuardConfiguration {

    public String getClaimsetKey();


	public long getCsrfTokenExpiresIn() ;

	public String getTokenName() ;
	public String getJavascriptTemplate();
	public String getTokenParamName();
	
	public Set<String> getFilterMethodsSet() ;
	public Set<String> getProtectedPages() ;
	public Set<String> getUnprotectedPages() ;

	
}
