import urllib, urllib2, requests, msgpack, base64

host = 'http://localhost:2501'

username = 'kismet'
password = 'kismet'

cmd = {
        "cmd": "hop",
        "channel": "1",
        "uuid": "ef9ac4da-0db8-11e6-b824-6205fb28e301",
        #"foo": "bar",
        }

invalid = [1, 4, 5, 6, 7]

rawdata = {
        "msgpack": base64.b64encode(msgpack.packb(cmd))
    }

invaliddata = {
        "msgpack": base64.b64encode(msgpack.packb(invalid))
    }


session = requests.Session()

session.auth = (username, password)
#print session.get("%s/session/create_session" % host).content

requests.utils.add_dict_to_cookiejar(session.cookies, {
    'KISMET': '87DEADAD9860A03B08C90CEAB0D6A861'
    })

print requests.utils.dict_from_cookiejar(session.cookies)

print session.get("%s/session/check_session" % host).content
print session.post("%s/packetsource/config/channel.cmd" % host, data=rawdata).content
#print session.post("%s/packetsource/config/channel.cmd" % host, data=invaliddata).content

