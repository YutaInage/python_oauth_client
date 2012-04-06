import urllib2

import oauth_client

class twitter_client(oauth_client.oauth_client):
    def __init__(self):
        self.auth_data["request_token_url"] = "http://api.twitter.com/oauth/request_token" # from http://dev.twitter.com/apps
        self.auth_data["access_token_url"] = "http://api.twitter.com/oauth/access_token" # from http://dev.twitter.com/apps
        self.auth_data["authorize_url"] = "http://api.twitter.com/oauth/authorize" # from http://dev.twitter.com/apps
        self.auth_data["oauth_signature_method"] = "HMAC-SHA1"
        self.auth_data["oauth_version"] = "1.0"

    def parse_access_token(self, in_access_token_data):
        result = {"oauth_token":"", "oauth_token_secret":"", "user_id":"", "screen_name":""}
        access_tokens = in_access_token_data.split("&")
        for token in access_tokens:
            parsed_token = token.split("=")

            if parsed_token[0].lower() == "oauth_token":
                result["oauth_token"] = parsed_token[1]

            if parsed_token[0].lower() == "oauth_token_secret":
                result["oauth_token_secret"] = parsed_token[1]

            if parsed_token[0].lower() == "user_id":
                result["user_id"] = parsed_token[1]
        
            if parsed_token[0].lower() == "screen_name":
                result["screen_name"] = parsed_token[1]

        return result

    def set_pincode(self, in_pincode):
        self.set_oauth_verifier(in_pincode)

    def get_auth_result(self):
        self.create_oauth_nonce()
        ret = self.create_oauth_signature("GET", self.signature_keys)

        url = self.create_request_token_url(self.request_token_keys)
        resp = urllib2.urlopen(url)
        resp_data = resp.read()
        self.parse_request_token(resp_data)

        url = self.create_authorize_url()
        print "access follwing url with browser and input PIN code"
        print url
        pin_code = raw_input(">")
        if len(pin_code) <= 0:
            print "[error] inval PIN code"
            return result

        self.set_pincode(pin_code)

        self.create_oauth_nonce()
        ret = self.create_oauth_signature("GET", self.signature_keys)
        url = self.create_access_token_url(self.access_token_keys)
        resp = urllib2.urlopen(url)
        resp_data = resp.read()
        result = self.parse_access_token(resp_data)

        return result

# sample application
twitter = twitter_client()
twitter.set_consumer_key("")
twitter.set_consumer_secret("")
result = twitter.get_auth_result()
print result



