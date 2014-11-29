AEM CSRF guard. This uses googlecode.jsontoken for generating csrf tokens. 
This approach used jwt(https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31)
  You can set token name, claimset name and token expiry time. As of now, the configurations for adding
  the token to the dom via javascript are not configurable.
 We can also add some pages that have to be protected via this and some pages that need not be protected at all

USAGE:
mvn clean install
In your page component jsp or sightly file, add &gt;script src="/bin/aem/csrfguard.js" /&lt;

And add a osgiconfig for com.adobe.users.kalyanar.csrf.CSRFGuardConfiguration
If this config is not available, then the guard will be disabled.
Modify csrfguard.js under src/main/resources to modify the js.
The js file is a version of https://github.com/aramrami/OWASP-CSRFGuard-3 

