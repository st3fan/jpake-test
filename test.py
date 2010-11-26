#!/usr/bin/python

import sys, time, urllib2, hmac, base64, binascii, random
try:
    import json as simplejson
except ImportError:
    import simplejson
from jpake import JPAKE, params_80, params_112, params_128
#from M2Crypto.EVP import Cipher, hmac
from hashlib import sha256, sha1

class PAKEClient (object):

    def __init__(self, server, password, identity, channel = None):
        self.password = password
        self.server = server
        self.identity = identity
        self.channel = channel
        self.session_id = ''.join(["%x" % random.randint(0,15) for i in range(256)])
        self.jpake = JPAKE(password, signerid=identity, params=params_128)
        self.key = None
        self.message_one = None
        self.message_one_etag = None
        self.remote_message_one = None
        self.message_two = None
        self.message_two_etag = None
        self.remote_message_two = None
        self.message_three = None
        self.message_three_etag = None
        self.remote_message_three = None
        pass

    def get(self, url, etag = None):
        headers = {'X-KeyExchange-Id': self.session_id}
        if etag:
            headers['If-None-Match'] = etag
        request = urllib2.Request(url, None, headers)
        response = urllib2.urlopen(request)
        data = response.read()
        return simplejson.loads(data)

    def get_message(self, etag = None):
        return self.get("%s/%s" % (self.server, self.channel), etag)

    def put(self, url, data):
        #print "X %s.put %s" % (self.identity, str(data))
        opener = urllib2.build_opener(urllib2.HTTPHandler)
        json = simplejson.dumps(data)
        request = urllib2.Request(url, data=json, headers={'X-KeyExchange-Id': self.session_id})
        request.add_header('Content-Type', 'application/json')
        request.get_method = lambda: 'PUT'
        response = urllib2.urlopen(request)
        return response.info().getheader('Etag')

    def put_message(self, data):
        return self.put("%s/%s" % (self.server, self.channel), data)

    def createChannel(self):
        print "X %s.createChannel" % self.identity
        self.channel = self.get("%s/new_channel" % self.server)
    
    def putMessageOne(self):
        print "X %s.putMessageOne" % self.identity
        self.message_one = { 'type': '%s1' % self.identity,
                             'payload': self.jpake.one() }
        self.message_one_etag = self.put_message(self.message_one)

    def getMessageOne(self):
        print "X %s.getMessageOne" % self.identity
        self.remote_message_one = self.get_message(self.message_one_etag)        

    def putMessageTwo(self):
        print "X %s.putMessageTwo" % self.identity
        self.message_two = { 'type': '%s2' % self.identity,
                             'payload': self.jpake.two(self.remote_message_one['payload']) }
        self.message_two_etag = self.put_message(self.message_two)

    def getMessageTwo(self):
        print "X %s.getMessageTwo" % self.identity
        self.remote_message_two = self.get_message(self.message_two_etag)

    def putMessageThree(self):
        print "X %s.putMessageThree" % self.identity
        self.key = self.jpake.three(self.remote_message_two['payload'])
        self.message_three = { 'type': '%s3' % self.identity,
                               'payload': sha256(sha256(self.key).digest()).hexdigest() }
        self.message_three_etag = self.put_message(self.message_three)

    def getMessageThree(self):
        print "X %s.getMessageThree" % self.identity
        self.remote_message_three = self.get_message(self.message_three_etag)
        
def main():
    
    if len(sys.argv) != 2:
        print "Usage: ./test.py server-url"
        sys.exit(1)

    server = sys.argv[1]
    password = ''.join([chr(random.randint(ord('a'), ord('z'))) for i in range(8)])

    print "X Server   : %s" % server
    print "X Password : %s" % password

    receiverSessionId = ''.join(["%x" % random.randint(0,15) for i in range(256)])
    senderSessionId = ''.join(["%x" % random.randint(0,15) for i in range(256)])
        
    receiver = PAKEClient(server, password, 'receiver')
    receiver.createChannel()

    print "X Channel : %s" % receiver.channel

    sender = PAKEClient(server, password, 'sender', receiver.channel)
    
    receiver.putMessageOne()
    sender.getMessageOne()
    sender.putMessageOne()
    receiver.getMessageOne()
    receiver.putMessageTwo()
    sender.getMessageTwo()
    sender.putMessageTwo()
    receiver.getMessageTwo()
    receiver.putMessageThree()
    sender.getMessageThree()
    sender.putMessageThree()
    receiver.getMessageThree()

    print "X Key receiver = %s" % sha256(receiver.key).hexdigest()
    print "X Key sender   = %s" % sha256(sender.key).hexdigest()

    if receiver.key != sender.key:
        raise Exception("Key Mismatch")

if __name__ == "__main__":
    main()
