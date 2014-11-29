package com.adobe.users.kalyanar.csrf.impl;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.JsonTokenParser;
import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.HmacSHA256Verifier;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.VerifierProvider;
import net.oauth.jsontoken.discovery.VerifierProviders;

import org.apache.commons.lang3.StringUtils;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;

import com.adobe.users.kalyanar.csrf.CSRFGuardConfiguration;
import com.adobe.users.kalyanar.csrf.JWTBuilder;

import com.google.common.collect.Lists;
import com.google.gson.JsonObject;
@Component(name="aem CSRF Guard JWTBuilder",description = "aem CSRF Guard JWT builder",metatype = false)
@Service
public class JWTBuilderImpl implements JWTBuilder {
private HmacSHA256Signer signer ;
private JsonTokenParser parser;

@Reference
private CSRFGuardConfiguration csrfConfig;

@Override
public String generateJsonWebToken(String userId){
	Calendar cal = Calendar.getInstance();
    
     //Configure JSON token
     JsonToken token = new net.oauth.jsontoken.JsonToken(signer);
     token.setAudience(csrfConfig.getTokenName());
     token.setIssuedAt(new org.joda.time.Instant(cal.getTimeInMillis()));
     token.setExpiration(new org.joda.time.Instant(cal.getTimeInMillis() + 1000L *csrfConfig.getCsrfTokenExpiresIn()));

     //Configure request object, which provides information of the item
     JsonObject request = new JsonObject();
     request.addProperty("userId", userId);

     JsonObject payload = token.getPayloadAsJsonObject();
     payload.add("info", request);

     try {
         return token.serializeAndSign();
     } catch (SignatureException e) {
         throw new RuntimeException(e);
     }
	
}

@Override
public boolean verifyToken(String token){

         JsonToken jt;
         try {
             jt = parser.verifyAndDeserialize(token);
         } catch (SignatureException e) {
             throw new RuntimeException(e);
         }
         JsonObject payload = jt.getPayloadAsJsonObject();
         String issuer = payload.getAsJsonPrimitive("iss").getAsString();
         String userIdString =  payload.getAsJsonObject("info").getAsJsonPrimitive("userId").getAsString();
         if (issuer.equals(csrfConfig.getTokenName()) && !StringUtils.isBlank(userIdString)){
        	 return true;
         }


	return false;
}

		@Activate
		@Modified
		private void activate(Map<String, Object> props) { 
			 try {
		         signer = new HmacSHA256Signer(csrfConfig.getTokenName(), null, csrfConfig.getClaimsetKey().getBytes());
		         final Verifier	hmacVerifier = new HmacSHA256Verifier(csrfConfig.getClaimsetKey().getBytes());
		 		VerifierProvider	hmacLocator = new VerifierProvider() {

			         @Override
			         public List<Verifier> findVerifier(String id, String key){
			             return Lists.newArrayList(hmacVerifier);
			         }
			     };
			     VerifierProviders  locators = new VerifierProviders();
		         locators.setVerifierProvider(SignatureAlgorithm.HS256, hmacLocator);
		         net.oauth.jsontoken.Checker checker = new net.oauth.jsontoken.Checker(){

		             @Override
		             public void check(JsonObject payload) throws SignatureException {
		                 // don't throw - allow anything
		             }

		         };
		         parser = new JsonTokenParser(locators,
		                 checker);
			 } catch (InvalidKeyException e) {
		         throw new RuntimeException(e);
		     }

		}
}
