import requests
import base64
import hashlib
import uuid

# Enter API Token from Okta tenant: https://developer.okta.com/docs/guides/create-an-api-token/overview/
API_Token = "API TOKEN"

# Enter your okta url
# Okta Url Format: subdomain.okta.com
okta_url = "subdomain.okta.com"
query_url = "https://" + okta_url + "/api/v1/users"


querystring = {"activate":"true"}


# Unecrypted values for Salt and Password
salt = "&*GAH*AO*AL)AF#P(AHG#A"
print ("salt unencrypted: " + salt)

password = "TestPw123"
print ("password unencrypted: " + password)
pw_salt = password + salt
print ("password + salt unencrypted: " + pw_salt)

print ("")
print ("")

# SHA512 encrypted password
pw_sha512 = hashlib.sha512(pw_salt).digest()
print ("pw + salt SHA512 encrypted: " + pw_sha512)

print ("")

pw_b64 = base64.b64encode(pw_sha512)
print ("sha512 pw base64 encrypted: " + pw_b64)
salt_b64 = base64.b64encode(salt) 
print ("salt base64 encrypted: " + salt_b64)





print ("")


payload = "{\n  \"profile\": {\n    \"firstName\": \"Isaac\",\n    \"lastName\": \"Brock\",\n    \"email\": \"isaac@willywonkta.com\",\n    \"login\": \"isaac@willywonkta.com\"\n  },\n  \"credentials\": {\n    \"password\" : {  \"hash\": {\n    \t\t\t\"algorithm\": \"SHA-512\",\n    \t\t\t\"salt\": \"%s\",\n    \t\t\t\"saltOrder\": \"POSTFIX\",\n\t\t\t\t\"value\": \"%s\"\n    \t} }\n  }\n}" % (salt_b64, pw_b64)


print (payload)

print (" ")

headers = {
    'Accept': "application/json",
    'Content-Type': "application/json",
    'Authorization': "SSWS " + API_TOKEN,
    }

response = requests.request("POST", query_url, data=str(payload), headers=headers, params=querystring)

print(response.text)