# -*- encoding: utf-8 -*-
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
    auth_header_keys = [
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

    def create_auth_header(self):
        header = "OAuth "
        for key in self.auth_header_keys:
            if len(self.auth_data[key]) > 0:
                header += key
                header += "=\""
                header += self.auth_data[key]
                header += "\", "

        header = header.rstrip(", ")

        return header

    def write_tweet(self, in_message):
        twitter_update_url = "https://api.twitter.com/1/statuses/update.json"
        msg = urllib.quote(
                unicode(in_message, "UTF-8").encode("UTF-8"),
                ""
                )
        self.auth_data["status"] = msg
        self.create_oauth_nonce()
        self.create_oauth_signature("POST", twitter_update_url, self.signature_keys)

        post_header = self.create_auth_header()
        req = urllib2.Request(twitter_update_url)
        req.add_header("Authorization", post_header)
        req.add_data("status=" + msg)

        resp = urllib2.urlopen(req)

    def read_tweet(self):
        print "unimplemented"

    def get_timeline(self, in_query = None):

        if in_query == None:
            in_query = {}

        keys = self.signature_keys + in_query.keys()
        twitter_timeline_url = "https://api.twitter.com/1/statuses/home_timeline.json"

        self.create_oauth_nonce()
        self.create_oauth_signature("GET", twitter_timeline_url, keys, in_query)

        auth_header = self.create_auth_header()

        query = urllib.urlencode(in_query)
        req = urllib2.Request(twitter_timeline_url + "?" + query)
        req.add_header("Authorization", auth_header)

        resp = urllib2.urlopen(req)
        
        return resp.read()



# OAuth sample application
#twitter = twitter_auth()
#twitter.set_consumer_key("")
#twitter.set_consumer_secret("")

#try:
#    result = twitter.get_auth_result()

#except urllib2.HTTPError, e:
#    print "[error] Failed send tweet (HTTP code " + str(e.code) + ")"

#except urllib2.URLError, e:
#    print "[error] Error URL"

#else:
#    print result

# tweet sample application
twitter = twitter_client()

ext_query= {"count" : "1"}

try:
    #twitter.write_tweet("てすと")
    print twitter.get_timeline(ext_query)

except urllib2.HTTPError, e:
    print "[error] Failed send tweet (HTTP code " + str(e.code) + ")"

except urllib2.URLError, e:
    print "[error] Error URL"


