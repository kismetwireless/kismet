#!/usr/bin/python

from lxml import etree

tree = etree.parse("contained.xml")

r = tree.xpath('/k:run/devices/device/deviceMac',
                namespaces={'k':'http://www.kismetwireless.net/xml'})

print len(r)

for e in r:
    print etree.tostring(e)
