# -*- encoding: utf-8 -*-

import sys
import urllib2
import urllib
import time
import hashlib
import random
import hmac
import hashlib
import urlparse
import base64


class oauth_client:
    auth_data = {
    "oauth_consumer_key" : "",
    "oauth_consumer_secret" : "",
    "request_token_url" : "",
    "authorize_url" : "",
    "access_token_url" : "",
    "oauth_token" : "",
    "oauth_token_secret" : "",
    "oauth_callback_confirmed" : "",
    "oauth_verifier" : "",
    "oauth_version" : "",
    "oauth_timestamp" : "",
    "oauth_nonce" : "",
    "oauth_signature_method" : "",
    "oauth_signature" : "",
    "oauth_callback" : "",
    "status" : "",
    "user_id" : "",
    "screen_name" : ""
    }

    signature_keys = [
    "oauth_consumer_key",
    "oauth_nonce",
    "oauth_signature_method",
    "oauth_timestamp",
    "oauth_token",
    "oauth_verifier",
    "oauth_version",
    "status"
    ]

    request_token_keys = [
    "oauth_callback",
    "oauth_consumer_key",
    "oauth_version",
    "oauth_timestamp",
    "oauth_nonce",
    "oauth_signature_method",
    "oauth_signature"
    ]    

    access_token_keys = [
    "oauth_consumer_key",
    "oauth_token",
    "oauth_timestamp",
    "oauth_nonce",
    "oauth_signature_method",
    "oauth_signature"
    ]

    def set_consumer_key(self, in_consumer_key):
        self.auth_data["oauth_consumer_key"] = in_consumer_key

    def set_consumer_secret(self, in_consumer_secret):
        self.auth_data["oauth_consumer_secret"] = in_consumer_secret

    def set_oauth_verifier(self, in_verifier):
        self.auth_data["oauth_verifier"] = in_verifier

    def set_oauth_token(self, in_token):
        self.auth_data["oauth_token"] = in_token

    def set_oauth_token_secret(self, in_secret):
        self.auth_data["oauth_token_secret"] = in_secret

    def create_oauth_nonce(self):
        nonce_seed = str(random.random())
        self.auth_data["oauth_nonce"] = hashlib.md5(nonce_seed).hexdigest()

    def create_oauth_signature(self, in_method, in_url, in_keys, in_ext_data = None):
        if in_method != "GET" and in_method != "POST":
            print "[error] inval method"
            return False

        self.auth_data["oauth_timestamp"] = str(int(time.time()))

        params = ""
        if in_ext_data is None:
            in_ext_data = {"":""}

        for key in sorted(in_keys):
            if self.auth_data.has_key(key) and len(self.auth_data[key]) > 0:
                params += key + "=" + self.auth_data[key] + "&"
            if in_ext_data.has_key(key) and len(in_ext_data[key]) > 0:
                params += key + "=" + in_ext_data[key] + "&"
            
        params = params.rstrip("&")

        signature_base_str = in_method
        signature_base_str += "&"
        signature_base_str += urllib2.quote(in_url, "")
        signature_base_str += "&"
        signature_base_str += urllib2.quote(params, "")

        signature_key = urllib2.quote(self.auth_data["oauth_consumer_secret"], "")
        signature_key += "&"
        signature_key += urllib2.quote(self.auth_data["oauth_token_secret"], "")

        self.auth_data["oauth_signature"] = urllib2.quote(
            base64.b64encode(
                hmac.new(signature_key, signature_base_str, hashlib.sha1).digest()
            ),
            ""
        )
        return True

    def create_request_token_url(self, in_keys):
        query = ""
        for key in in_keys:
            if len(self.auth_data[key]) > 0:
                query += key + "=" + self.auth_data[key] + "&"

        query = query.rstrip("&")
        url = self.auth_data["request_token_url"]
        url += "?"
        url += query

        return url

    def parse_request_token(self, in_request_token_data):
        request_tokens = in_request_token_data.split("&")
        for token in request_tokens:
            parsed_token = token.split("=")

            if parsed_token[0].lower() == "oauth_token":
                self.auth_data["oauth_token"] = parsed_token[1]

            if parsed_token[0].lower() == "oauth_token_secret":
                self.auth_data["oauth_token_secret"] = parsed_token[1]

            if parsed_token[0].lower() == "oauth_callback_confirmed":
                self.auth_data["oauth_callback_confirmed"] = parsed_token[1]


    def create_access_token_url(self, in_keys):
        query = ""
        for key in in_keys:
           if len(self.auth_data[key]) > 0:
               query += key + "=" + self.auth_data[key] + "&"

        query = query.rstrip("&")
        url = self.auth_data["access_token_url"]
        url += "?"
        url += query
        return url

    def create_authorize_url(self):
        url = self.auth_data["authorize_url"]
        url += "?"
        url += "oauth_token=" + self.auth_data["oauth_token"]
        return url

    def set_oauth_verifier(self, in_verifier):
        self.auth_data["oauth_verifier"] = in_verifier

