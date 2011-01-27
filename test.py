#!/usr/bin/python

import sys, time, urllib2, hmac, base64, binascii, random
try:
    import json as simplejson
except ImportError:
    import simplejson
from jpake import JPAKE, params_80, params_112, params_128
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
        start = time.time()
        response = urllib2.urlopen(request)
        data = response.read()
        duration = time.time() - start
        return (duration, simplejson.loads(data))

    def get_message(self, etag = None):
        return self.get("%s/%s" % (self.server, self.channel), etag)

    def put(self, url, data):
        #print "X %s.put %s" % (self.identity, str(data))
        opener = urllib2.build_opener(urllib2.HTTPHandler)
        json = simplejson.dumps(data)
        request = urllib2.Request(url, data=json, headers={'X-KeyExchange-Id': self.session_id})
        request.add_header('Content-Type', 'application/json')
        request.get_method = lambda: 'PUT'
        start = time.time()
        response = urllib2.urlopen(request)
        duration = time.time() - start
        return (duration, response.info().getheader('Etag'))

    def put_message(self, data):
        return self.put("%s/%s" % (self.server, self.channel), data)

    def createChannel(self):
        #print "X %s.createChannel" % self.identity
        (duration, self.channel) = self.get("%s/new_channel" % self.server)
        print "OK %0.4f %s CREATE" % (duration, self.identity)
    
    def putMessageOne(self):
        #print "X %s.putMessageOne" % self.identity
        self.message_one = { 'type': '%s1' % self.identity,
                             'payload': self.jpake.one() }
        (duration, self.message_one_etag) = self.put_message(self.message_one)
        print "OK %.04f %s PUT 1" % (duration, self.identity)

    def getMessageOne(self):
        #print "X %s.getMessageOne" % self.identity
        (duration, self.remote_message_one) = self.get_message(self.message_one_etag)        
        print "OK %0.4f %s GET 1" % (duration, self.identity)

    def putMessageTwo(self):
        #print "X %s.putMessageTwo" % self.identity
        self.message_two = { 'type': '%s2' % self.identity,
                             'payload': self.jpake.two(self.remote_message_one['payload']) }
        (duration, self.message_two_etag) = self.put_message(self.message_two)
        print "OK %0.4f %s PUT 2" % (duration, self.identity)

    def getMessageTwo(self):
        #print "X %s.getMessageTwo" % self.identity
        (duration, self.remote_message_two) = self.get_message(self.message_two_etag)
        print "OK %0.4f %s GET 2" % (duration, self.identity)

    def putMessageThree(self):
        #print "X %s.putMessageThree" % self.identity
        self.key = self.jpake.three(self.remote_message_two['payload'])
        self.message_three = { 'type': '%s3' % self.identity,
                               'payload': sha256(sha256(self.key).digest()).hexdigest() }
        (duration, self.message_three_etag) = self.put_message(self.message_three)
        print "OK %0.4f %s PUT 3" % (duration, self.identity)

    def getMessageThree(self):
        #print "X %s.getMessageThree" % self.identity
        (duration, self.remote_message_three) = self.get_message(self.message_three_etag)
        print "OK %0.4f %s GET 1" % (duration, self.identity)
        
def main():
    
    if len(sys.argv) != 2:
        print "Usage: ./test.py server-url"
        sys.exit(1)

    server = sys.argv[1]
    password = ''.join([chr(random.randint(ord('a'), ord('z'))) for i in range(8)])

    #print "X Server   : %s" % server
    #print "X Password : %s" % password

    receiverSessionId = ''.join(["%x" % random.randint(0,15) for i in range(256)])
    senderSessionId = ''.join(["%x" % random.randint(0,15) for i in range(256)])
        
    receiver = PAKEClient(server, password, 'receiver')
    receiver.createChannel()

    #print "X Channel : %s" % receiver.channel

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

    #print "X Key receiver = %s" % sha256(receiver.key).hexdigest()
    #print "X Key sender   = %s" % sha256(sender.key).hexdigest()

    if receiver.key != sender.key:
        raise Exception("Key Mismatch")

if __name__ == "__main__":
    main()
