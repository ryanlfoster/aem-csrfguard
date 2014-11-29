AEM CSRF guard. This uses googlecode.jsontoken for generating csrf tokens. 
This approach used jwt(https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31)
  You can set token name, claimset name and token expiry time. As of now, the configurations for adding
  the token to the dom via javascript are not configurable.
 We can also add some pages that have to be protected via this and some pages that need not be protected at all
