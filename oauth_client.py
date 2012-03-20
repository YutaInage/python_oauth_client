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
    "oauth_version"
]

request_token_keys = [
    # "oauth_callback",
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

def create_oauth_signature(method, keys, data):
    if method != "GET" and method != "POST":
	print "[error] inval method"
	return False

    data["oauth_timestamp"] = str(int(time.time()))

    params = ""
    for key in sorted(keys):
	if len(data[key]) > 0:
	   params += key + "=" + data[key] + "&"
    params = params.rstrip("&")

    signature_base_str = method
    signature_base_str += "&"
    signature_base_str += urllib2.quote(data["request_token_url"], "")
    signature_base_str += "&"
    signature_base_str += urllib2.quote(params, "")
    signature_key = urllib2.quote(data["oauth_consumer_secret"], "")
    signature_key += "&"
    signature_key += urllib2.quote(data["oauth_token_secret"], "")

    data["oauth_signature"] = urllib2.quote(
	base64.b64encode(
	    hmac.new(signature_key, signature_base_str, hashlib.sha1).digest()
	),
	""
    )
    return True
    

def create_oauth_nonce(data):
    nonce_seed = str(random.random())
    data["oauth_nonce"] = hashlib.md5(nonce_seed).hexdigest()
    return True


def oauth_init(consumer_key, consumer_secret, data):
    data["oauth_consumer_key"] = consumer_key
    data["oauth_consumer_secret"] = consumer_secret
    data["request_token_url"] = "http://api.twitter.com/oauth/request_token" # from http://dev.twitter.com/apps
    data["access_token_url"] = "http://api.twitter.com/oauth/access_token" # from http://dev.twitter.com/apps
    data["authorize_url"] = "http://api.twitter.com/oauth/authorize" # from http://dev.twitter.com/apps
    data["oauth_signature_method"] = "HMAC-SHA1"
    data["oauth_version"] = "1.0"
    return True


def create_request_token_url(keys, data):
    query = ""
    for key in keys:
	if len(data[key]) > 0:
	    query += key + "=" + data[key] + "&"
    query = query.rstrip("&")
    
    url = data["request_token_url"]
    url += "?"
    url += query
    return url


def parse_request_token(request_token_data, data):
    request_tokens = request_token_data.split("&")
    for token in request_tokens:
	parsed_token = token.split("=")

	if parsed_token[0].lower() == "oauth_token":
	    data["oauth_token"] = parsed_token[1]

	if parsed_token[0].lower() == "oauth_token_secret":
	    data["oauth_token_secret"] = parsed_token[1]

	if parsed_token[0].lower() == "oauth_callback_confirmed":
	    data["oauth_callback_confirmed"] = parsed_token[1]

    return True


def create_authorize_url(data):
    url = data["authorize_url"]
    url += "?"
    url += "oauth_token=" + data["oauth_token"]
    return url


def create_access_token_url(keys, data):
    query = ""
    for key in keys:
	if len(data[key]) > 0:
	    query += key + "=" + data[key] + "&"
    query = query.rstrip("&")
    
    url = data["access_token_url"]
    url += "?"
    url += query
    return url


def parse_access_token(access_token_data, data):
    access_tokens = access_token_data.split("&")
    for token in access_tokens:
	parsed_token = token.split("=")

	if parsed_token[0].lower() == "oauth_token":
	    data["oauth_token"] = parsed_token[1]

	if parsed_token[0].lower() == "oauth_token_secret":
	    data["oauth_token_secret"] = parsed_token[1]

	if parsed_token[0].lower() == "user_id":
	    data["user_id"] = parsed_token[1]
	    
	if parsed_token[0].lower() == "screen_name":
	    data["screen_name"] = parsed_token[1]

    return True


# application start
print "input consumer key"
consumer_key = raw_input(">")
if len(consumer_key) <= 0:
    print "[error] inval consumer key"
    sys.exit()

print "input consumer secret"
consumer_secret = raw_input(">")
if len(consumer_secret) <= 0:
    print "[error] inval consumer secret"
    sys.exit()

oauth_init(consumer_key, consumer_secret, auth_data)
create_oauth_nonce(auth_data)
ret = create_oauth_signature("GET", signature_keys, auth_data)
if ret != True:
    sys.exit()

# get request-token
url = create_request_token_url(request_token_keys, auth_data)
resp = urllib2.urlopen(url)
resp_data = resp.read()
ret = parse_request_token(resp_data, auth_data)

# request-token authorize
url = create_authorize_url(auth_data)
print "access follwing url with browser and input PIN code"
print url
pin_code = raw_input(">")
if len(pin_code) <= 0:
    print "[error] inval PIN code"
    sys.exit()

auth_data["oauth_verifier"] = pin_code

# get access-token
create_oauth_nonce(auth_data)
ret = create_oauth_signature("GET", signature_keys, auth_data)
if ret != True:
    sys.exit()

url = create_access_token_url(access_token_keys, auth_data)
resp = urllib2.urlopen(url)
resp_data = resp.read()
ret = parse_access_token(resp_data, auth_data)
print "success OAuth authorization !"
print "oauth token        : " + auth_data["oauth_token"]
print "oauth token secret : " + auth_data["oauth_token_secret"]
print "user id            : " + auth_data["user_id"]
print "screen name        : " + auth_data["screen_name"]


