# Error: no grant_type
curl -vvv -H "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" \
    http://localhost:8070/oauth2/token

# Error: unsupported grant_type
curl -vvv -H "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" \
    -d "grant_type=refresh_token" \
    http://localhost:8070/oauth2/token

# Basic authentication, no scopes requested
curl -vvv -H "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" \
    -d "grant_type=client_credentials" \
    http://localhost:8070/oauth2/token

# Basic authentication, valid scopes requested
curl -vvv -H "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" \
    -d "grant_type=client_credentials&scope=aaa  bbb  ccc" \
    http://localhost:8070/oauth2/token

# Basic authentication, invalid scopes requested
curl -vvv -H "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" \
    -d "grant_type=client_credentials&scope=" \
    http://localhost:8070/oauth2/token

# Post authentication, no scopes requested
curl -vvv \
    -d "grant_type=client_credentials&client_id=Aladdin&client_secret=sesame" \
    http://localhost:8070/oauth2/token

# Post authentication, valid scopes requested
curl -vvv \
    -d "grant_type=client_credentials&client_id=Aladdin&client_secret=sesame&scope=aaa  bbb  ccc" \
    http://localhost:8070/oauth2/token

# Post authentication, invalid scopes requested
curl -vvv \
    -d "grant_type=client_credentials&client_id=Aladdin&client_secret=sesame&scope=" \
    http://localhost:8070/oauth2/token

