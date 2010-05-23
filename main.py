"""
OAuth code is based on example at http://github.com/tav/tweetapp
"""

import sys
import logging
import re

from datetime import datetime, timedelta
from hashlib import sha1
from hmac import new as hmac
from os.path import dirname, join as join_path
from random import getrandbits
from time import time
from urllib import urlencode, quote as urlquote
from uuid import uuid4
from wsgiref.handlers import CGIHandler

sys.path.insert(0, join_path(dirname(__file__), 'lib')) # extend sys.path

from demjson import decode as decode_json

from google.appengine.api.urlfetch import fetch as urlfetch, GET, POST
from google.appengine.ext import db
from google.appengine.ext.webapp import RequestHandler, WSGIApplication
from google.appengine.api import users
from google.appengine.api import xmpp
from google.appengine.api.labs import taskqueue
from google.appengine.api import memcache

# ------------------------------------------------------------------------------
# configuration -- SET THESE TO SUIT YOUR APP!!
# ------------------------------------------------------------------------------

OAUTH_APP_SETTINGS = {

    'twitter': {

        'consumer_key': 'PROVIDE-YOUR-CONSUMER-KEY',
        'consumer_secret': 'PROVIDE-YOUR-CONSUMER-SECRET',

        'request_token_url': 'https://twitter.com/oauth/request_token',
        'access_token_url': 'https://twitter.com/oauth/access_token',
        'user_auth_url': 'http://twitter.com/oauth/authorize',
        

        'default_api_prefix': 'http://twitter.com',
        'default_api_suffix': '.json',

        'bitly_url_prefix' : 'http://api.bit.ly/v3/shorten?format=txt&login=PROVIDE_USERNAME&apiKey=PROVIDE_API_KEY&longUrl=',

        },

    }

CLEANUP_BATCH_SIZE = 100
EXPIRATION_WINDOW = timedelta(seconds=60*60*1) # 1 hour

try:
    from config import OAUTH_APP_SETTINGS
except:
    pass

STATIC_OAUTH_TIMESTAMP = 12345 # a workaround for clock skew/network lag

# ------------------------------------------------------------------------------
# utility functions
# ------------------------------------------------------------------------------

def get_service_key(service, cache={}):
    if service in cache: return cache[service]
    return cache.setdefault(
        service, "%s&" % encode(OAUTH_APP_SETTINGS[service]['consumer_secret'])
        )

def create_uuid():
    return 'id-%s' % uuid4()

def encode(text):
    return urlquote(str(text), '')

def twitter_specifier_handler(client):
    return client.get('/account/verify_credentials')['screen_name']

OAUTH_APP_SETTINGS['twitter']['specifier_handler'] = twitter_specifier_handler

# ------------------------------------------------------------------------------
# db entities
# ------------------------------------------------------------------------------

class OAuthRequestToken(db.Model):
    """OAuth Request Token."""

    service = db.StringProperty()
    oauth_token = db.StringProperty()
    oauth_token_secret = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

class OAuthAccessToken(db.Model):
    """OAuth Access Token."""
    service = db.StringProperty()
    specifier = db.StringProperty()
    oauth_token = db.StringProperty()
    oauth_token_secret = db.StringProperty()
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

   
# ------------------------------------------------------------------------------
# oauth client
# ------------------------------------------------------------------------------

class OAuthClient(object):

    __public__ = ('callback', 'cleanup', 'login', 'logout')

    def __init__(self, service, handler, email=None, oauth_callback=None, **request_params):
        self.service = service
        self.service_info = OAUTH_APP_SETTINGS[service]
        self.service_key = None
        self.handler = handler
        self.request_params = request_params
        self.oauth_callback = oauth_callback
        self.token = None
        self.email = email

    # public methods

    def get(self, api_method, http_method='GET', expected_status=(200,), **extra_params):

        if not (api_method.startswith('http://') or api_method.startswith('https://')):
            api_method = '%s%s%s' % (
                self.service_info['default_api_prefix'], api_method,
                self.service_info['default_api_suffix']
                )

        if self.token is None:
            '''self.token = OAuthAccessToken.get_by_key_name(self.get_cookie())'''
            self.token = getAccessToken(self.email)

        fetch = urlfetch(self.get_signed_url(
            api_method, self.token, http_method, **extra_params
            ))

        if fetch.status_code not in expected_status:
            raise ValueError(
                "Error calling... Got return status: %i [%r]" %
                (fetch.status_code, fetch.content)
                )

        return decode_json(fetch.content)

    def post(self, api_method, http_method='POST', expected_status=(200,), **extra_params):

        if not (api_method.startswith('http://') or api_method.startswith('https://')):
            api_method = '%s%s%s' % (
                self.service_info['default_api_prefix'], api_method,
                self.service_info['default_api_suffix']
                )

        if self.token is None:
            '''self.token = OAuthAccessToken.get_by_key_name(self.get_cookie())'''
            tokens = OAuthAccessToken.all().filter(
                'email =', self.email)
            
            for token in tokens:
                self.token = token


        fetch = urlfetch(url=api_method, payload=self.get_signed_body(
            api_method, self.token, http_method, **extra_params
            ), method=http_method)

        if fetch.status_code not in expected_status:
            raise ValueError(
                "Error calling... Got return status: %i [%r]" %
                (fetch.status_code, fetch.content)
                )

        return decode_json(fetch.content)

    def login(self):

        proxy_id = self.get_cookie()

        if proxy_id:
            return "FOO%rFF" % proxy_id

        return self.get_request_token()

    def logout(self, return_to='/'):
        self.expire_cookie()
        self.handler.redirect(self.handler.request.get("return_to", return_to))

    # oauth workflow

    def get_request_token(self):

        token_info = self.get_data_from_signed_url(
            self.service_info['request_token_url'], **self.request_params
            )

        token = OAuthRequestToken(
            service=self.service,
            **dict(token.split('=') for token in token_info.split('&'))
            )

        token.put()

        if self.oauth_callback:
            oauth_callback = {'oauth_callback': self.oauth_callback}
        else:
            oauth_callback = {}

        self.handler.redirect(self.get_signed_url(
            self.service_info['user_auth_url'], token, **oauth_callback
            ))

    def callback(self, return_to='/'):

        oauth_token = self.handler.request.get("oauth_token")

        if not oauth_token:
            return get_request_token()

        oauth_token = OAuthRequestToken.all().filter(
            'oauth_token =', oauth_token).filter(
            'service =', self.service).fetch(1)[0]

        token_info = self.get_data_from_signed_url(
            self.service_info['access_token_url'], oauth_token
            )

        key_name = create_uuid()

        self.token = OAuthAccessToken(
            key_name=key_name, service=self.service,
            **dict(token.split('=') for token in token_info.split('&'))
            )

        if 'specifier_handler' in self.service_info:
            specifier = self.token.specifier = self.service_info['specifier_handler'](self)
            old = OAuthAccessToken.all().filter(
                'specifier =', specifier).filter(
                'service =', self.service)
            
            for obj in old:
                db.delete(obj)
        
        user = users.get_current_user()
        self.token.email = user.email()
        self.token.put()
        self.set_cookie(key_name)
        self.handler.redirect(return_to)

    def cleanup(self):
        query = OAuthRequestToken.all().filter(
            'created <', datetime.now() - EXPIRATION_WINDOW
            )
        count = query.count(CLEANUP_BATCH_SIZE)
        db.delete(query.fetch(CLEANUP_BATCH_SIZE))
        return "Cleaned %i entries" % count

    # request marshalling

    def get_data_from_signed_url(self, __url, __token=None, __meth='GET', **extra_params):
        return urlfetch(self.get_signed_url(
            __url, __token, __meth, **extra_params
            )).content

    def get_signed_url(self, __url, __token=None, __meth='GET',**extra_params):
        return '%s?%s'%(__url, self.get_signed_body(__url, __token, __meth, **extra_params))

    def get_signed_body(self, __url, __token=None, __meth='GET',**extra_params):

        service_info = self.service_info

        kwargs = {
            'oauth_consumer_key': service_info['consumer_key'],
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_version': '1.0',
            'oauth_timestamp': int(time()),
            'oauth_nonce': getrandbits(64),
            }

        kwargs.update(extra_params)

        if self.service_key is None:
            self.service_key = get_service_key(self.service)

        if __token is not None:
            kwargs['oauth_token'] = __token.oauth_token
            key = self.service_key + encode(__token.oauth_token_secret)
        else:
            key = self.service_key

        message = '&'.join(map(encode, [
            __meth.upper(), __url, '&'.join(
                '%s=%s' % (encode(k), encode(kwargs[k])) for k in sorted(kwargs)
                )
            ]))

        kwargs['oauth_signature'] = hmac(
            key, message, sha1
            ).digest().encode('base64')[:-1]

        return urlencode(kwargs)

    # who stole the cookie from the cookie jar?

    def get_cookie(self):
        return self.handler.request.cookies.get(
            'oauth.%s' % self.service, ''
            )

    def set_cookie(self, value, path='/'):
        self.handler.response.headers.add_header(
            'Set-Cookie', 
            '%s=%s; path=%s; expires="Fri, 31-Dec-2021 23:59:59 GMT"' %
            ('oauth.%s' % self.service, value, path)
            )

    def expire_cookie(self, path='/'):
        self.handler.response.headers.add_header(
            'Set-Cookie', 
            '%s=; path=%s; expires="Fri, 31-Dec-1999 23:59:59 GMT"' %
            ('oauth.%s' % self.service, path)
            )

# ------------------------------------------------------------------------------
# oauth handler
# ------------------------------------------------------------------------------

class OAuthHandler(RequestHandler):

    def get(self, service, action=''):

        if service not in OAUTH_APP_SETTINGS:
            return self.response.out.write(
                "Unknown OAuth Service Provider: %r" % service
                )

        client = OAuthClient(service, self)

        if action in client.__public__:
            self.response.out.write(getattr(client, action)())
        else:
            self.response.out.write(client.login())

# ------------------------------------------------------------------------------
# modify this demo MainHandler to suit your needs
# ------------------------------------------------------------------------------

HEADER = """
  <html><head><title>Tweet on IM</title>
  </head><body>
  <h1>Get Twitter on your GTalk!</h1>
  """

FOOTER = "</body></html>"

CONTENT = """<p>Add tweetonim@appspot.com as your GTalk buddy and type 'help' </p>
<p>For feedback, tweet @vishalmanohar </p>
"""

HELP = """
Type 'fetch' to get latest tweets from homepage
Type 'fetch <screenname>' to get latest tweets by screenname'
Type 'more' to go deeeper on any previous fetch of tweets
Type 'lists' to list all your lists
Type 'list N' to show tweets from the Nth list
Type 'RT N' to retweet the Nth tweet of the most recent fetch
Type 'reply N' to reply to a tweet
Type a message to post to Twitter
"""

class BaseRequestHandler(RequestHandler):
    def fetchTweets(self, client, email, api_method, **extra_params):
        response = client.get(api_method, **extra_params)
        
        user_cache = UserCache(email, api_method, **extra_params)
        messages = []
        if len(response) > 0:
            user_cache.max_id  = response[len(response) - 1]["id"]
            user_cache.since_id = response[0]["id"]
            
        user_cache.messages = response
        
        memcache.set("user_cache_" + email, user_cache)
        
        return response

class MainHandler(RequestHandler):
    """Demo Twitter App."""

    def get(self):
        user = users.get_current_user()
        if user:
            client = OAuthClient('twitter', self, user.email())
    
            write = self.response.out.write; write(HEADER)
    
            if not client.get_cookie():
                write('<a href="/oauth/twitter/login">Grant access to Twitter</a>')
                write(FOOTER)
                return
    
            write('<a href="/oauth/twitter/logout">Revoke access to Twitter</a><br /><br />')
    
            write(CONTENT)
            write(FOOTER)
        else:
            self.redirect(users.create_login_url("/"))
            

class XMPPHandler(BaseRequestHandler):
    def post(self):
        message = xmpp.Message(self.request.POST)
        sender = getUserEmailId(message.sender)

        client = OAuthClient('twitter', self, sender)
        
        if message.body[0:4].lower() == 'help':
            message.reply(HELP)
        elif message.body.strip().lower() == 'fetch':
            response = self.fetchTweets(client, sender, 
                                   '/statuses/home_timeline', count = 5)
            message.reply(getFormattedMessage(response))
        elif message.body[0:5].strip().lower() == 'fetch':
            screenname = message.body.replace('fetch', '', 1).strip()
            response = self.fetchTweets(client, sender, 
                                   '/statuses/user_timeline', 
                                   screen_name = screenname, count = 5)
            message.reply(getFormattedMessage(response))
        elif message.body.strip().lower() == 'more':
            user_cache = memcache.get("user_cache_" + sender)
            if user_cache is not None:
                params = user_cache.extraparams
                params['max_id'] = user_cache.max_id
                
                if 'since_id' in params:
                    params.pop('since_id')
    
                response = self.fetchTweets(client, sender, user_cache.api_method, 
                                            **params)
                message.reply(getFormattedMessage(response))
            else:
                message.reply("Don't remember previous query. Please fetch afresh.")
        elif message.body.strip().lower() == 'lists':
            token = getAccessToken(sender)
            response = client.get('/' + token.specifier + '/lists')
            message.reply(getFormattedListMessage(response))
            
        elif message.body[0:4].strip().lower() == 'list':
            list_index = int(message.body.replace('list', '', 1).strip().strip('@'))
            token = getAccessToken(sender)
            client.token = token
            
            lists = client.get('/' + token.specifier + '/lists')['lists']
            
            if len(lists) == 0 or len(lists) < list_index:
                message.reply('Incorrect list index given.')
            else:
                list_id = str(lists[list_index - 1]["id"])
                logging.info('/' + token.specifier + '/lists/' 
                                   + list_id)
                response = self.fetchTweets(client, sender, 
                                   '/' + token.specifier + '/lists/' 
                                   + list_id + '/statuses', per_page = 5)
                message.reply(getFormattedMessage(response))
        elif message.body[0:2].strip().lower() == 'rt' and len(message.body) <= 6:
            message_index = int(message.body.strip('RT').strip('rt').
                                replace('@', '').strip())
            user_cache = memcache.get("user_cache_" + sender)
            if len(user_cache.messages) < message_index:
                message.reply("@"+ message_index 
                              + " message index doesn't exist in my cache.")
            else:
                message_id = user_cache.messages[message_index - 1]["id"]
                client.post('/statuses/retweet/' + str(message_id))
                tweet = user_cache.messages[message_index - 1]
                message.reply('Retweeted: RT @' +  tweet["user"]["screen_name"] 
                              + ' ' + tweet["text"])
        elif message.body[0:6].lower() == 'reply ':
            message_index = int(message.body.split(' ')[1].
                                replace('@', '').strip())
            user_cache = memcache.get("user_cache_" + sender)
            
            if len(user_cache.messages) < message_index:
                message.reply("@"+ message_index 
                              + " message index doesn't exist in my cache.")
            else:
                message_id = user_cache.messages[message_index - 1]["id"]
                reply_to_author = user_cache.messages[message_index - 1]["user"]["screen_name"] 
                parts = message.body.split(' ')
                
                msg = '@' + reply_to_author + ' ' + message.body.replace(parts[0], '').replace(parts[1], '').strip()
                
                if len(msg) > 140:
                    message.reply('Reply to message exceeds 140 char limit by ' + 
                              str(len(msg) - 140) + ' chars.')
                else:
                    client.post('/statuses/update', status = msg, in_reply_to_status_id = message_id)
                    message.reply('Posted to Twitter: ' + msg)
                
        else:
            tweet = message.body
            #try to shorten any link
            r = re.compile(r"(http://[^ ]+)")
            match = r.search(tweet)

            if match is not None:
                link = match.group()
                #link = urllib.quote_plus(link)
                result = urlfetch(OAUTH_APP_SETTINGS['twitter']['bitly_url_prefix'] + link)
                if result.status_code == 200:
                    short_link = result.content
                    tweet = tweet.replace(link, short_link)
                
            if len(tweet) > 140:
                message.reply('Exceeds 140 char limit by ' + 
                              str(len(tweet) - 140) + ' chars.')
            else:
                client.post('/statuses/update', status = tweet)
                message.reply('Posted to Twitter')

class SendRecentHandler(RequestHandler):
    def get(self):
        taskqueue.add(url='/sendrecentworker', params={'cursor': 0})


class SendRecentWorker(BaseRequestHandler):
    def post(self):
        cursor = int(self.request.get("cursor", default_value=0))
        tokens = OAuthAccessToken.all().fetch(10, offset = cursor)

        for token in tokens:
            if xmpp.get_presence(token.email):
                client = OAuthClient('twitter', self, token.email)
                
                user_cache = memcache.get("user_cache_" + token.email)
                
                if user_cache is not None and user_cache.since_id is not None:
                    #response = client.get('/statuses/home_timeline', count = 5, 
                    #                  since_id = last_sent_id)
                    logging.info('since_id:' +  str(user_cache.since_id))
                    response = self.fetchTweets(client, token.email, 
                                    '/statuses/home_timeline', count = 5, 
                                      since_id = user_cache.since_id)
                else:
                    response = self.fetchTweets(client, token.email, 
                                    '/statuses/home_timeline', count = 5)
                
                if len(response) > 0:
                    xmpp.send_message(token.email, 'Some recent tweets:' + getFormattedMessage(response))
        
        if len(tokens) == 10:
            taskqueue.add(url='/sendrecentworker', 
                          params={'cursor': cursor + 10})

            
class UserCache:
    def __init__(self, email, api_method, **extraparams):
        self.email = email
        self.api_method = api_method
        self.extraparams = extraparams
        self.since_id = None
        self.max_id = None
        self.messages = None
        
def getUserEmailId(string):
    return string.partition('/')[0]

def getFormattedMessage(messages):
    msg = ''
    count = 1
    for message in messages:
        msg = msg + '\n' + str(count) + ' *' + message["user"]["screen_name"] + '*: ' + message["text"]
        count = count + 1
    
    return msg

def getFormattedListMessage(response):
    
    lists = response['lists']
    
    msg = 'You are following these lists:'
    count = 1
    
    for lst in lists:
        msg = msg + '\n ' + str(count) + ' ' + lst["name"]
        count = count + 1
        
    if count == 1:
        return 'You are not following any lists yet.' 
    
    return msg

def getAccessToken(email):
    tokens = OAuthAccessToken.all().filter('email =', email)
    for token in tokens:
        return token
    
# ------------------------------------------------------------------------------
# self runner -- gae cached main() function
# ------------------------------------------------------------------------------

def main():

    application = WSGIApplication([
       ('/oauth/(.*)/(.*)', OAuthHandler),
       ('/_ah/xmpp/message/chat/', XMPPHandler),
       ('/sendrecent', SendRecentHandler),
       ('/sendrecentworker', SendRecentWorker),
       ('/', MainHandler)
       ], debug=True)

    CGIHandler().run(application)

if __name__ == '__main__':
    main()
