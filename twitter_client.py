import urllib
import urllib2

import oauth_client

class twitter_auth(oauth_client.oauth_client):
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
        ret = self.create_oauth_signature("GET", self.auth_data["request_token_url"], self.signature_keys)

        url = self.create_request_token_url(self.request_token_keys)

        try:
            resp = urllib2.urlopen(url)
        except urllib2.HTTPError, e:
            print "[error] Failed request token authorize (HTTP code " + str(e.code) + ")"
            return ""
        except urllib2.URLError, e:
            print "[error] URL error"
            return ""

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
        ret = self.create_oauth_signature("GET", self.auth_data["request_token_url"], self.signature_keys)
        url = self.create_access_token_url(self.access_token_keys)

        try:
            resp = urllib2.urlopen(url)
        except urllib2.HTTPError, e:
            print "[error] Failed access token authorize (HTTP code " + str(e.code) + ")"
            return ""
        except urllib2.URLError, e:
            print "[error] URL error"
            return ""

        resp_data = resp.read()
        result = self.parse_access_token(resp_data)

        return result


class twitter_client(oauth_client.oauth_client):
    post_header_keys = [
        "oauth_consumer_key",
        "oauth_token",
        "oauth_version",
        "oauth_timestamp",
        "oauth_nonce",
        "oauth_signature_method",
        "oauth_signature"
    ]

    def __init__(self):
        self.auth_data["request_token_url"] = "http://api.twitter.com/oauth/request_token" # from http://dev.twitter.com/apps
        self.auth_data["access_token_url"] = "http://api.twitter.com/oauth/access_token" # from http://dev.twitter.com/apps
        self.auth_data["authorize_url"] = "http://api.twitter.com/oauth/authorize" # from http://dev.twitter.com/apps
        self.auth_data["oauth_signature_method"] = "HMAC-SHA1"
        self.auth_data["oauth_version"] = "1.0"

    def create_post_header(self):
        post_header = "OAuth "
        for key in self.post_header_keys:
            if len(self.auth_data[key]) > 0:
                post_header += key
                post_header += "=\""
                post_header += self.auth_data[key]
                post_header += "\", "

        post_header = post_header.rstrip(", ")

        return post_header

    def write_tweet(self, in_message):
        twitter_update_url = "https://api.twitter.com/1/statuses/update.json"
        msg = urllib.quote(
                unicode(in_message, "UTF-8").encode("UTF-8"),
                ""
                )
        self.auth_data["status"] = msg
        self.create_oauth_nonce()
        self.create_oauth_signature("POST", twitter_update_url, self.signature_keys)

        post_header = self.create_post_header()
        req = urllib2.Request(twitter_update_url)
        req.add_header("Authorization", post_header)
        req.add_data("status=" + msg)

        try:
            resp = urllib2.urlopen(req)
        except urllib2.HTTPError, e:
            print "[error] Failed send tweet (HTTP code " + str(e.code) + ")"
        except urllib2.URLError, e:
            print "[error] Error URL"

    def read_tweet(self):
        print "unimplemented"

# OAuth sample application
twitter = twitter_auth()
twitter.set_consumer_key("")
twitter.set_consumer_secret("")
result = twitter.get_auth_result()
print result

# tweet sample application
twitter = twitter_client()
twitter.set_consumer_key("")
twitter.set_consumer_secret("")
twitter.set_oauth_token("")
twitter.set_oauth_token_secret("")
twitter.write_tweet("tweet message")

