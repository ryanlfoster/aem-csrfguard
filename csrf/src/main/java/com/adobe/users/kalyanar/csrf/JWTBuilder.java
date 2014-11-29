package com.adobe.users.kalyanar.csrf;
/**
 * This uses google jsontoken to generate the jwt(https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31)
 * The token generated will have a configurable expiry time. the default is set as 10 minutes.
 * All configurations are via CSRFGuardConfigurationImpl
 * @author kalyanar
 *
 */
public interface JWTBuilder {
	/**
	 * To verify the jwt token.
	 * @param token
	 * @return
	 */
	 boolean verifyToken(String token);
	 
	 /**
	  * to generate the jwt token
	  * @param userId
	  * @return
	  */
	 String generateJsonWebToken(String userId);
}
