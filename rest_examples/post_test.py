import urllib, urllib2, requests, msgpack, base64

host = 'http://localhost:2501'

username = 'kismet'
password = 'kismet'

cmd = {
        "cmd": "lock",
        "channel": "6HT20",
        "time": 10,
        "source": "aaa:bbb:cc:dd:ee:ff:gg"
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
print session.get("%s/session/create_session" % host).content
print session.get("%s/session/check_session" % host).content
print session.post("%s/packetsource/config_source.cmd" % host, data=rawdata).content
print session.post("%s/packetsource/config_source.cmd" % host, data=invaliddata).content

