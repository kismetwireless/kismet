#!/usr/bin/python

"""
    Kismet GPS Mapping

    Rewritten - better, faster, stronger, able to leap tall XML files in a 
    single bound, using modern map repositories.

    Map repo code ported to python from Maemo Mapper, Copyright (c) 2004-2006 
    by John Costigan.  The algorithm magic is all his.

    Unless otherwise noted, (c) Mike Kershaw, dragorn@kismetwireless.net

    GPL v2
"""

# Import Psyco if available - why does this only speed up the second time?
# meh, whatever
try:
    import psyco
    psyco.full()
except ImportError:
    print "NOTICE: Psyco not found, things may be slower but it is not required."
    pass

import os, sys, time, xml.sax.handler, getopt, ConfigParser, md5, string
from decimal import *
from math import *
from urllib import urlretrieve

try:
    import gd
except ImportError:
    print "ERROR: Kismap requires gdmodule from:"
    print "   http://newcenturycomputers.net/projects/gdmodule.html"
    print "(or check your distribution packages)"
    raise

class TileMap:
    """
    Map coordinates onto a tile, and fetch tiles into a cached directory.
    """
    def __init__(self, zoom_mod = 0, url = None, cachedir = None, tiletype = "png"):
        self.zmod = zoom_mod
        self.cachedir = cachedir
        self.url = url
        self.tiletype = tiletype

        # Constants from Maemo-Mapper
        self.MERCATOR_SPAN = (-6.28318377773622)
        self.MERCATOR_TOP = (3.14159188886811)
        self.TILE_SIZE_PIXELS = (256)
        self.TILE_SIZE_P2 = (8)
        self.MIN_ZOOM = (0)
        self.MAX_ZOOM = (20)
        self.WORLD_SIZE_UNITS = (2 << (self.MAX_ZOOM + self.TILE_SIZE_P2))

        self.min_xtile = 0
        self.min_ytile = 0
        self.max_xtile = 0
        self.max_ytile = 0
        self.zoom = 0

        self.px = -1
        self.py = -1

    def CoordToUnit(self, lat, lon):
        """ Convert lat,lon to a unit coodinate on the projection """
        dlat = float(lat)
        dlon = float(lon)

        ux = (dlon + 180.0) * (self.WORLD_SIZE_UNITS / 360.0) + 0.5
        tmp = sin(dlat * (pi / 180.0))
        uy = 0.50 + (self.WORLD_SIZE_UNITS / self.MERCATOR_SPAN) 
        uy = uy * (log((1.0 + tmp) / (1.0 - tmp)) * 0.50 - self.MERCATOR_TOP);

        return (int(ux), int(uy))

    def UnitToZTile(self, unit, zoom):
        """ Return the tile that contains a unit """
        return ((unit) >> (self.TILE_SIZE_P2 + (zoom + self.zmod)))

    def TileToZUnit(self, tile, zoom):
        """ Return the unit coordinates of the top-left of a tile """
        return ((tile) << (self.TILE_SIZE_P2 + (zoom + self.zmod)))

    def UnitToZPixel(self, unit, zoom):
        """ Return the pixel coordinates of a unit """
        return ((unit) >> (zoom + self.zmod))

    def TileToPixel(self, tile):
        """ Return the pixel coordinates of a tile """
        return ((tile) << self.TILE_SIZE_P2)

    def TilesToZURL(self, tx, ty, zoom):
        if self.url == None:
            return None

        urldict = { }
        urldict["xtile"] = str(tx)
        urldict["ytile"] = str(ty)
        urldict["zoom"] = zoom

        return self.url % urldict

    def DownloadTileImage(self, tx, ty, zoom, destination):
        url = self.TilesToZURL(tx, ty, zoom)

        if url == None:
            return

        print "Debug - Downloading", url

        if (os.access(destination, os.R_OK) == False):
            urlretrieve(url, destination)
        else:
            print "Debug - Not downloading, already cached"

    def PrepCoords(self, min_lat, min_lon, max_lat, max_lon, zoom):
        """ Set the coordinates for future prepped ops """
        minux, minuy = self.CoordToUnit(min_lat, min_lon)
        maxux, maxuy = self.CoordToUnit(max_lat, max_lon)

        self.min_xtile = self.UnitToZTile(minux, zoom)
        self.min_ytile = self.UnitToZTile(minuy, zoom)

        self.max_xtile = self.UnitToZTile(maxux, zoom)
        self.max_ytile = self.UnitToZTile(maxuy, zoom)

        if (self.max_xtile < self.min_xtile):
            mx = self.min_xtile
            self.min_xtile = self.max_xtile
            self.max_xtile = mx

        if (self.max_ytile < self.min_ytile):
            my = self.min_ytile
            self.min_ytile = self.max_ytile
            self.max_ytile = my

        self.zoom = zoom

        self.min_xtile = self.min_xtile - 1
        self.min_ytile = self.min_ytile - 1
        self.max_xtile = self.max_xtile + 1
        self.max_ytile = self.max_ytile + 1

        print self.min_xtile, self.min_ytile, self.max_xtile, self.max_ytile

    def FetchTileCount(self):
        """ Total # of tiles we'll download after prepping coords """
        xrange = self.max_xtile - self.min_xtile
        yrange = self.max_ytile - self.min_ytile

        if (xrange == 0):
            xrange = 1
        if (yrange == 0):
            yrange = 1

        return xrange * yrange

    def DownloadTiles(self):
        for x in range(self.min_xtile, self.max_xtile):
            # Cache in cache/zoom/coord/y.png
            cachedir = self.cachedir + "/" + str(self.zoom) + "/" + str(x)
            if (os.access(cachedir, os.W_OK) == False):
                os.makedirs(cachedir)
            for y in range(self.min_ytile, self.max_ytile):
                cachefile = cachedir + "/" + str(y) + "." + self.tiletype
                self.DownloadTileImage(x, y, self.zoom, cachefile)

    def FetchStitchedImage(self):
        """ Return a stitched image of all the points """
        self.DownloadTiles()

        xrange = self.max_xtile - self.min_xtile
        yrange = self.max_ytile - self.min_ytile

        if (xrange == 0):
            xrange = 1
        if (yrange == 0):
            yrange = 1

        imgw = xrange * self.TILE_SIZE_PIXELS
        imgh = yrange * self.TILE_SIZE_PIXELS

        print "Allocating image ", imgw, "x", imgh

        img = gd.image((imgw, imgh), 1)

        if self.url != None:
            for x in range(self.min_xtile, self.max_xtile):
                for y in range(self.min_ytile, self.max_ytile):
                    tileimg = gd.image(self.cachedir + "/" + str(self.zoom) + "/" + str(x) + "/" + str(y) + "." + self.tiletype)
                    xpos = (x - self.min_xtile) * self.TILE_SIZE_PIXELS
                    ypos = (y - self.min_ytile) * self.TILE_SIZE_PIXELS
                    tileimg.copyTo(img, (xpos, ypos))
        else:
            rectclr = img.colorAllocate((255, 255, 255))
            img.rectangle((0, 0), (imgw, imgh), rectclr, rectclr)

        return img

    def CoordToPrepPixel(self, lat, lon):
        spux = self.TileToZUnit(self.min_xtile, self.zoom)
        spuy = self.TileToZUnit(self.min_ytile, self.zoom)

        sppx = self.UnitToZPixel(spux, self.zoom)
        sppy = self.UnitToZPixel(spuy, self.zoom)

        ux, uy = self.CoordToUnit(lat, lon)

        upx = self.UnitToZPixel(ux, self.zoom)
        upy = self.UnitToZPixel(uy, self.zoom)

        return ((upx - sppx), (upy - sppy))

class GpsPoint:
    """
    Representation of a GPS point from the gpsxml file
    Uses math.decimal to prevent float manipulation errors in lat/lon
    over massive averaging, etc
    """
    def __init__(self, xml = None, txt = None):
        if xml != None:
            try:
                self.bssid = xml["bssid"]
                self.source = xml["source"]

                self.timesec = int(xml["time-sec"])
                self.timeusec = int(xml["time-usec"])

                self.lat = Decimal(xml["lat"])
                self.lon = Decimal(xml["lon"])
                self.alt = Decimal(xml["alt"])
                self.spd = Decimal(xml["spd"])
                self.heading = Decimal(xml["heading"])
                self.fix = int(xml["fix"])

                self.signal = int(xml["signal"])
                self.noise = int(xml["noise"])
            except:
                raise
        elif txt != None:
            try:
                ta = string.split(txt, "\001")

                self.bssid = ta[0]
                self.source = ta[1]
                self.timesec = int(ta[2])
                self.timeusec = int(ta[3])
                self.lat = Decimal(ta[4])
                self.lon = Decimal(ta[5])
                self.alt = Decimal(ta[6])
                self.spd = Decimal(ta[7])
                self.heading = Decimal(ta[8])
                self.fix = int(ta[9])
                self.signal = int(ta[10])
                self.noise = int(ta[11])
            except:
                raise
        else:
            self.bssid = ""
            self.source = ""

            self.timesec = 0
            self.timeusec = 0

            self.lat = Decimal(0)
            self.lon = Decimal(0)
            self.alt = Decimal(0)
            self.spd = Decimal(0)
            self.heading = Decimal(0)
            self.fix = 0

            self.signal = 0
            self.noise = 0

            self.zpx = 0
            self.zpy = 0

            self.avgcenter_px = -1
            self.avgcenter_py = -1

    def Cache(self):
        r = []
        r.append(self.bssid)
        r.append(self.source)
        r.append(str(self.timesec))
        r.append(str(self.timeusec))
        r.append(str(self.lat))
        r.append(str(self.lon))
        r.append(str(self.alt))
        r.append(str(self.spd))
        r.append(str(self.heading))
        r.append(str(self.fix))
        r.append(str(self.signal))
        r.append(str(self.noise))

        return "\001".join(r)

class GpsNetwork:
    """
    Representation of a network from netxml
    Less than a Kismet network definition and not a full representation
    of the data kept in the netxml record, because we don't need it
    """
    def __init__(self, xml = None):
        self.points = []

        self.min_lat = Decimal("90")
        self.min_lon = Decimal("180")
        self.max_lat = Decimal("-90")
        self.max_lon = Decimal("-180")

        self.avgcenter_px = -1
        self.avgcenter_py = -1

        self.clients = { }

        self.sorted = 0
        self.sorted_points = []

        self.sorted_min_lat = Decimal("90")
        self.sorted_min_lon = Decimal("180")
        self.sorted_max_lat = Decimal("-90")
        self.sorted_max_lon = Decimal("-180")

        self.sorted_avgcenter_px = -1
        self.sorted_avgcenter_py = -1

        if xml == None:
            self.ssid = []
            self.bssid = ""
            self.channel = 0
            self.maxrate = float(0)
            self.carrier = ""
            self.encryption = ""
            self.type = ""
            self.cloaked = 0

class GpsClient:
    """
    Limited representation of a network client
    """
    def __init__(self, xml = None):
        self.source = ""
        self.points = []

        self.min_lat = Decimal("90")
        self.min_lon = Decimal("180")
        self.max_lat = Decimal("-90")
        self.max_lon = Decimal("-180")

        self.avgcenter_px = -1
        self.avgcenter_py = -1

def sort_pt_alg_lat(x, y):
    if x.lat < y.lat:
        return -1
    elif x.lat == y.lat:
        return 0
    else:
        return 1

def sort_pt_alg_lon(x, y):
    if x.lon < y.lon:
        return -1
    elif x.lon == y.lon:
        return 0
    else:
        return 1

def sort_pt_alg_time(x, y):
    if x.timesec < y.timesec:
        return -1
    elif x.timesec == y.timesec:
        if x.timeusec < y.timeusec:
            return -1
        elif x.timeusec == y.timeusec:
            return 0
        else:
            return 1
    else:
        return 1

class KismetStblGpsHandler(xml.sax.handler.ContentHandler):
    """ 
    XML handlers for kismet-stable gpsxml files
    """
    def __init__(self):
        self.networks = { }
        self.gpspoints = []

        self.start_time = 0

        self.in_run = 0
        self.in_netfile = 0

        self.netfile = ""

        self.filtered = 0

    def NumPoints(self):
        return len(self.gpspoints)

    def startElement(self, name, attributes):
        if (name == "network-file"):
            self.in_netfile = 1
        elif (name == "gps-point"):
            try:
                gp = GpsPoint(attributes)
                self.gpspoints.append(gp)
            except:
                print "Error on GPS point"

    def characters(self, data):
        if (self.in_netfile):
            self.netfile = data

    def endelement(self, name):
        if (name == "network-file" and self.in_netfile):
            self.in_netfile = 0

    def FetchPoints(self):
        return self.gpspoints

    def LoadCache(self, fname):
        try:
            cf = open(fname, 'r')
        except:
            print "INFO: Couldn't open cache file", fname
            return 0

        print "INFO:  Loading from cache file", fname

        try:
            self.start_time = int(cf.readline())
        except:
            print "ERROR: Invalid start time in cache", fname
            return 0

        try:
            self.netfile = cf.readline()[:-1]
        except:
            print "ERROR: Invalid netfile in cache", fname
            return 0

        for g in cf.readlines():
            try:
                gp = GpsPoint(txt = g)
            except:
                print "ERROR:  Invalid gps point in cache", fname
                return len(self.gpspoints)

            self.gpspoints.append(gp)

        cf.close()

        self.filtered = 1

        return 1

    def SaveCache(self, fname):
        try:
            cf = open(fname, 'w')
        except:
            print "INFO: Couldn't open cache file", fname, "for writing"
            return 0

        cf.write("%s\n" % self.start_time)
        cf.write("%s\n" % self.netfile)
        for g in self.gpspoints:
            cf.write("%s\n" % g.Cache())

        cf.close()

        return 1

class KismetStblNetHandler(xml.sax.handler.ContentHandler):
    """ 
    XML handlers for kismet-stable gpsxml files
    """
    def __init__(self):
        self.networks = { }
        self.clients = { }
        self.gpspoints = []

        self.start_time = 0

        self.in_run = 0
        self.in_netfile = 0

        self.netfile = ""

    def NumPoints(self):
        return len(self.gpspoints)

    def startElement(self, name, attributes):
        if (name == "network-file"):
            self.in_netfile = 1
        elif (name == "gps-point"):
            gp = GpsPoint(attributes)
            self.gpspoints.append(gp)

    def characters(self, data):
        if (self.in_netfile):
            self.netfile = data

    def endelement(self, name):
        if (name == "network-file" and self.in_netfile):
            self.in_netfile = 0

    def FetchPoints(self):
        return self.gpspoints

class GpsAggregate:
    """
    Aggregate GPS data of multiple points, what gets plotted out to file
    """

    def __init__(self, verbose = 0):
        self.networks = { }
        self.tracks = []

        self.min_lat = Decimal("90")
        self.min_lon = Decimal("180")
        self.max_lat = Decimal("-90")
        self.max_lon = Decimal("-180")

        self.num = 0

        self.image = None
        self.tilemapper = None
        self.verbose = verbose

    def AddMapper(self, image, tilemapper):
        self.image = image
        self.tilemapper = tilemapper

    def AddGpsXML(self, xmlhandler):
        points = xmlhandler.FetchPoints()

        if xmlhandler.filtered == 0:
            if self.verbose:
                print "Filtering points..."
            self.FilterPoints(points)

        self.tracks.append([])
        for i in range(0, len(points)):
            # Throw out bogus points that still have a "valid" fix
            if points[i].lat == 0 and points[i].lon == 0 and points[i].alt == 0:
                continue

            # Add it to the track list
            if (points[i].bssid == "GP:SD:TR:AC:KL:OG"):
                self.tracks[self.num].append(points[i])
            else:
                curnet = None
                if (self.networks.has_key(points[i].bssid)):
                    curnet = self.networks[points[i].bssid]
                else:
                    curnet = GpsNetwork()
                    curnet.bssid = points[i].bssid
                    self.networks[points[i].bssid] = curnet

                curnet.points.append(points[i])

                if (points[i].bssid != points[i].source):
                    curcli = None
                    if curnet.clients.has_key(points[i].source):
                        curcli = curnet.clients[points[i].source]
                    else:
                        curcli = GpsClient()
                        curcli.source = points[i].source
                        curnet.clients[points[i].source] = curcli

                    curcli.points.append(points[i])

            # Combine it with the bounds
            if (points[i].lat < self.min_lat):
                self.min_lat = points[i].lat
            if (points[i].lon < self.min_lon):
                self.min_lon = points[i].lon

            if (points[i].lat > self.max_lat):
                self.max_lat = points[i].lat
            if (points[i].lon > self.max_lon):
                self.max_lon = points[i].lon

        self.num = self.num + 1

    def FilterPoints(self, pointlist, threshold = Decimal("0.5")):
        """
        Filter out junk data points caused by GPS noise or other nonsense
        that got into the data.  Filter by sorting and looking for gaps 
        greater than the threshold value: this seems to be a fairly accurate
        and relatively quick way to sort out the bunk points, and far better
        than trying to walk the path and look for outliers

        * Sort by (lat|lon)
        * Walk lower half (incrementing)
        * Get trim value
        * Walk upper half (decrementing)
        * Get trim value
        * Trim
        """

        lower_slice_point = -1
        upper_slice_point = -1

        pointlist.sort(sort_pt_alg_lon)

        for i in range(1, len(pointlist) / 2):
            offt = abs(pointlist[i].lon - pointlist[i - 1].lon)
            if (offt > threshold):
                lower_slice_point = i
        
        for i in range(len(pointlist) - 1, len(pointlist) / 2, -1):
            offt = abs(pointlist[i].lon - pointlist[i - 1].lon)
            if (offt > threshold):
                upper_slice_point = i

        if (lower_slice_point > 0 or upper_slice_point > 0):
            if (lower_slice_point < 0):
                lower_slice_point = 0
            if (upper_slice_point > len(pointlist)):
                upper_slice_point = len(pointlist)

            pointlist = pointlist[lower_slice_point:upper_slice_point]

        lower_slice_point = -1
        upper_slice_point = -1

        pointlist.sort(sort_pt_alg_lat)

        for i in range(1, len(pointlist) / 2):
            offt = abs(pointlist[i].lat - pointlist[i - 1].lat)
            if (offt > threshold):
                lower_slice_point = i
        
        for i in range(len(pointlist) - 1, len(pointlist) / 2, -1):
            offt = abs(pointlist[i].lat - pointlist[i - 1].lat)
            if (offt > threshold):
                upper_slice_point = i

        if (lower_slice_point > 0 or upper_slice_point > 0):
            if (lower_slice_point < 0):
                lower_slice_point = 0
            if (upper_slice_point > len(pointlist)):
                upper_slice_point = len(pointlist)

            pointlist = pointlist[lower_slice_point:upper_slice_point]

        pointlist.sort(sort_pt_alg_time)

        return pointlist

    def ProcessNetworkdata(self):
        """ 
        Process network points and get centers, etc 

        Call after all networks are added and dispersed through the
        aggregation.
        """
        for k in self.networks.keys():
            curnet = self.networks[k]

            avgpx = 0
            avgpy = 0
            avgc = 0
            lastlat = 0
            lastlon = 0

            for p in curnet.points:
                """ Cache the pixel-zoom location """
                p.px, p.py = self.tilemapper.CoordToPrepPixel(p.lat, p.lon)

                if (p.lat < curnet.min_lat):
                    curnet.min_lat = p.lat
                if (p.lon < curnet.min_lon):
                    curnet.min_lon = p.lon
                if (p.lat > curnet.max_lat):
                    curnet.max_lat = p.lat
                if (p.lon > curnet.max_lon):
                    curnet.max_lon = p.lon

                """ Average the network center based on integer math to avoid 
                    floating point rounding nonsense """
                if not lastlat == p.lat or not lastlon == p.lon:
                    lastlat = p.lat
                    lastlon = p.lon
                    avgpx = avgpx + p.px
                    avgpy = avgpy + p.py
                    avgc = avgc + 1

            curnet.avgcenter_px = int(avgpx / avgc)
            curnet.avgcenter_py = int(avgpy / avgc)

            curnet.sorted_points = self.FilterPoints(curnet.points, Decimal("0.0005"))

            avgpx = 0
            avgpy = 0
            avgc = 0
            lastlat = 0
            lastlon = 0

            for p in curnet.sorted_points:
                # Don't use clients in the network sorting, only beacons (or at 
                # least, only traffic FROM the AP) to prevent severe distortion
                # from spurious outliers
                if not p.source == p.bssid:
                    continue

                if (p.lat < curnet.sorted_min_lat):
                    curnet.sorted_min_lat = p.lat
                if (p.lon < curnet.sorted_min_lon):
                    curnet.sorted_min_lon = p.lon
                if (p.lat > curnet.sorted_max_lat):
                    curnet.sorted_max_lat = p.lat
                if (p.lon > curnet.sorted_max_lon):
                    curnet.sorted_max_lon = p.lon

                if not lastlat == p.lat or not lastlon == p.lon:
                    lastlat = p.lat
                    lastlon = p.lon
                    avgpx = avgpx + p.px
                    avgpy = avgpy + p.py
                    avgc = avgc + 1

            if not avgc == 0:
                curnet.sorted_avgcenter_px = int(avgpx / avgc)
                curnet.sorted_avgcenter_py = int(avgpy / avgc)

            curnet.sorted = 1

            """ Average the client locations """
            for c in curnet.clients.values():
                avgpx = 0
                avgpy = 0
                avgc = 0
                lastlat = 0
                lastlon = 0

                for p in c.points:
                    if not lastlat == p.lat or not lastlon == p.lon:
                        lastlat = p.lat
                        lastlon = p.lon
                        avgpx = avgpx + p.px
                        avgpy = avgpy + p.py
                        avgc = avgc + 1
            
                c.avgcenter_px = int(avgpx / avgc)
                c.avgcenter_py = int(avgpy / avgc)

        for t in self.tracks:
            for p in t:
                p.px, p.py = self.tilemapper.CoordToPrepPixel(p.lat, p.lon)

    def DrawTracks(self, rgb, trackwidth, simplify = 1, rgbmod = (0, 0, 10)):
        """ Draw tracks """
        for t in self.tracks:
            trackclr = self.image.colorAllocate(rgb)
            self.image.setThickness(trackwidth)

            for p in range(0, len(t) - simplify, simplify):
                ex = t[p + simplify].px
                ey = t[p + simplify].py
                self.image.line((t[p].px, t[p].py), (ex, ey), trackclr)

    def DrawNetCenters(self, rgb, diameter):
        """
        Draw network center points w/ raw averaging of the center.

        Use converted pixel coordinates of points to minimize
        float errors which happen when we use lat/lon
        """

        netclr = self.image.colorAllocate(rgb)
        self.image.setThickness(3)

        for n in self.networks.values():
            if n.sorted_avgcenter_py < 0 or n.sorted_avgcenter_px < 0:
                continue

            cpx = n.sorted_avgcenter_px - (diameter / 2)
            cpy = n.sorted_avgcenter_py - (diameter / 2)

            self.image.filledArc((cpx, cpy), (diameter, diameter), 0, 360, netclr, 4)

    def DrawClientLinks(self, rgb, diameter, lines = 1):
        netclr = self.image.colorAllocate(rgb)
        self.image.setThickness(1)

        for n in self.networks.values():
            if n.sorted_avgcenter_py < 0 or n.sorted_avgcenter_px < 0:
                continue

            npx = n.sorted_avgcenter_px
            npy = n.sorted_avgcenter_py

            for c in n.clients.values():
                if c.avgcenter_py < 0 or c.avgcenter_px < 0:
                    continue

                cpx = c.avgcenter_px - (diameter / 2)
                cpy = c.avgcenter_py - (diameter / 2)

                self.image.filledArc((cpx, cpy), (diameter, diameter), 0, 360, netclr, 0)

                if lines:
                    self.image.line((c.avgcenter_px, c.avgcenter_py), (npx, npy), netclr)


    def DrawNetRects(self, rgb, linewidth):
        rectclr = self.image.colorAllocate(rgb)
        self.image.setThickness(linewidth)

        for n in self.networks.values():
            sx, sy = self.tilemapper.CoordToPrepPixel(n.min_lat, n.min_lon)
            ex, ey = self.tilemapper.CoordToPrepPixel(n.max_lat, n.max_lon)

            if ex < sx:
                tx = sx
                sx = ex
                ex = tx

            if ey < sy:
                ty = sy
                sy = ey
                ey = ty

            if ex - sx > 50:
                print "debug -", n.max_lat - n.min_lat, n.max_lon - n.min_lon

            self.image.rectangle((sx, sy), (ex, ey), rectclr)

    def DrawNetRangeCircs(self, rgba):
        circclr = self.image.colorAllocateAlpha(rgba)
        self.image.setThickness(1)

        for n in self.networks.values():
            if n.sorted_avgcenter_py < 0 or n.sorted_avgcenter_px < 0:
                continue

            sx, sy = self.tilemapper.CoordToPrepPixel(n.sorted_min_lat, n.sorted_min_lon)
            ex, ey = self.tilemapper.CoordToPrepPixel(n.sorted_max_lat, n.sorted_max_lon)

            if ex < sx:
                tx = sx
                sx = ex
                ex = tx

            if ey < sy:
                ty = sy
                sy = ey
                ey = ty

            diagonal = sqrt(((ex-sx)*(ex-sx)) + (((ey-sy)*(ey-sy))))
            cpx = sx + ((ex - sx) / 2)
            cpy = sy + ((ey - sy) / 2)

            self.image.filledArc((cpx, cpy), (diagonal, diagonal), 0, 360, circclr, 0)

    def DrawNetHull(self):
        hullclr = self.image.colorAllocate((255, 0, 0, 50))

def help():
    print "%s [opts] [gpsxml files]" % sys.argv[0]
    print " -v/--verbose            Verbose output"
    print " -o/--output-image       Image to write"
    print " -z/--zoom               Zoom level"
    print " -C/--config             Alternate config file"
    print " -c/--center             Center of map (lat,lon)"
    print " -r/--radius             Radius (in miles) to plot around center"

def BoundingSquare(lat, lon, r):
    rlat = (lat * pi) / 180
    rlon = (lon * pi) / 180
    # Earth in KM
    R = 6371
    d = float(r)/R

    a = 0
    tlat = asin(sin(rlat) * cos(d) + cos(rlat) * sin(d) * cos(a))
    tlon = ((rlon + atan2(sin(a) * sin(d) * cos(rlat), cos(d) - sin(rlat) * sin(tlat))) * 180) / pi
    tlat = (tlat * 180) / pi
    maxlat = tlat

    a = 270 * pi / 180
    tlat = asin(sin(rlat) * cos(d) + cos(rlat) * sin(d) * cos(a))
    tlon = ((rlon + atan2(sin(a) * sin(d) * cos(rlat), cos(d) - sin(rlat) * sin(tlat))) * 180) / pi
    tlat = (tlat * 180) / pi
    maxlon = tlon

    a = 90
    tlat = asin(sin(rlat) * cos(d) + cos(rlat) * sin(d) * cos(a))
    tlon = ((rlon + atan2(sin(a) * sin(d) * cos(rlat), cos(d) - sin(rlat) * sin(tlat))) * 180) / pi
    tlat = (tlat * 180) / pi
    minlon = tlon

    a = 180 
    tlat = asin(sin(rlat) * cos(d) + cos(rlat) * sin(d) * cos(a))
    tlon = ((rlon + atan2(sin(a) * sin(d) * cos(rlat), cos(d) - sin(rlat) * sin(tlat))) * 180) / pi
    tlat = (tlat * 180) / pi
    minlat = tlat

    return (minlat, minlon, maxlat, maxlon)

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvz:o:C:c:r:",
            ["help", "verbose", "zoom", "output-image", "config", "center", "radius"])
    except getopt.error, msg:
        print msg
        print "For help, %s --help" % sys.argv[0]
        sys.exit(2)

    conf_main = {
        "name": "KisMap",
        "mapsource": "blank",
        "cachemaps": "true",
        "zoom": "3",
        "filename": "kismap.png",
        "cachexml": "true",
        "cachedir": ".",
        "map-center": "",
        "map-radius": ""
    }

    conf_drawing = {
        "tracks": "true",
        "powermap": "false",
        "bounds": "false",
        "range": "true",
        "hull": "false",
        "scatter": "false",
        "center": "true",
        "netlabels": "false",
        "clientlabels": "false",
        "legend": "true"
    }

    conf_map = {
        "url": None,
        "zoomadjust": "4"
    }

    xml.sax.handler.feature_external_ges = 0
    xml.sax.handler.feature_external_pes = 0

    verbose = 0
    cfvalid = 0

    #confdir = os.path.expanduser("~/.kismet")
    confdir = "."
    conffile = os.path.join(confdir, "kismap.conf")

    cfparser = ConfigParser.SafeConfigParser()

    # Parse just the config option
    for o, a in opts:
        if o in ("-C", "--config"):
            conffile = a

    cf = None

    print "debug - looking at conf file %s" % conffile
    try:
        cf = open(conffile, "r")
    except:
        print "Failed to open config file %s" % conffile
        raise

    try:
        cfparser.readfp(cf)
        cfvalid = 1
    except:
        print "Failed to parse config file %s" % conffile
        raise

    if cfvalid:
        conf_main.update(cfparser.items("main"))
        conf_drawing.update(cfparser.items("drawing"))
        conf_map.update(cfparser.items("map_%s" % conf_main["mapsource"]))

        try:
            confdir = os.path.expanduser(conf_main["cachedir"])
            conf_main["cachedir"] = confdir
        except:
            print "ERROR:  No 'confdir' in Main section"
            raise
            
        try:
            conf_main["zoom"] = int(conf_main["zoom"])
        except:
            print "ERROR:  Main::Zoom must be an integer"
            raise

        try:
            conf_map["zoomadjust"] = int(conf_map["zoomadjust"])
        except:
            print "ERROR: Map::Zoomadjust must be an integer"
            raise

    for o, a in opts:
        if o in ("-h", "--help"):
            help()
            sys.exit(0)
        elif o in ("-v", "--verbose"):
            verbose = 1
        elif o in ("-z", "--zoom"):
            try:
                conf_main["zoom"] = int(a)
            except:
                print "Zoom must be an integer"
                sys.exit(2)
        elif o in ("-o", "--output-image"):
            conf_main["filename"] = a
        elif o in ("-c", "--center"):
            conf_main["map-center"] = a
        elif o in ("-r", "--radius"):
            conf_main["map-radius"] = a

    if len(args) == 0:
        print "Specify at least one XML file"
        sys.exit(2)

    # Set math.decimal context up
    DefaultContext.prec = 6
    DefaultContext.rounding = ROUND_DOWN
    DefaultContext.traps = ExtendedContext.traps.copy()
    DefaultContext.traps[InvalidOperation] = 1
    setcontext(DefaultContext)

    agg = GpsAggregate(verbose = verbose)

    if (os.access(confdir, os.W_OK) == False):
        os.makedirs(confdir)
    
    for f in args:
        cached = 0
        cfname = ""
        parser = xml.sax.make_parser()
        handler = KismetStblGpsHandler()
        parser.setContentHandler(handler)

        if verbose:
            print "Processing XML file", f

        if conf_main["cachexml"] == "true":
            try:
                xf = open(f, 'r')
            except:
                print "ERROR:  Could not open", f, " for reading"
                raise

            m = md5.new()
            m.update(xf.read())

            xf.close()

            cfname = os.path.join(conf_main["cachedir"], "xmlcache")
            if (os.access(cfname, os.W_OK) == False):
                os.makedirs(cfname)
            cfname = os.path.join(cfname, m.hexdigest())

            if handler.LoadCache(cfname):
                cached = 1

        if cached == 0:
            try:
                parser.parse(f)
            except xml.sax._exceptions.SAXParseException:
                print "*** XML parser failed, atempting to use what we've got"

        if verbose:
            print "Number of points parsed, ", handler.NumPoints()

        if handler.NumPoints() > 0:
            agg.AddGpsXML(handler)

        if conf_main["cachexml"] == "true" and cached == 0:
            handler.SaveCache(cfname)

    if verbose:
        print "Map %f,%f by %f,%f" % (agg.min_lat, agg.min_lon, agg.max_lat, agg.max_lon)

    # Set up the tilemap handler
    tilecache = os.path.join(confdir, "%s-cache" % conf_main["mapsource"])
    if verbose:
        print "Caching tiles in", tilecache
    tm = TileMap(conf_map["zoomadjust"], url = conf_map["url"], cachedir = tilecache)

    if verbose:
        print "Using zoom", conf_main["zoom"]

    if (conf_main["map-center"] == ""):
        tm.PrepCoords(agg.min_lat, agg.min_lon, agg.max_lat, agg.max_lon, conf_main["zoom"])
    else:
        try:
            (slat,slon) = string.split(conf_main["map-center"], ",")
            clat = float(slat)
            clon = float(slon)
        except:
            print "Invalid map center, expected lat,lon"
            raise

        (minlat,minlon,maxlat,maxlon) = BoundingSquare(clat, clon, float(conf_main["map-radius"]))

        tm.PrepCoords(minlat, minlon, maxlat, maxlon, conf_main["zoom"])
    
    if verbose:
        print "Needs", tm.FetchTileCount(), "tiles"

    img = tm.FetchStitchedImage()

    agg.AddMapper(img, tm)

    if verbose:
        print "Processing network data"
    agg.ProcessNetworkdata()

    if not conf_drawing["tracks"] == "false":
        if verbose:
            print "Drawing tracks"
        agg.DrawTracks((0, 0, 255), 8, simplify = 10)

    if not conf_drawing["bounds"] == "false":
        if verbose:
            print "Network rects"
        agg.DrawNetRects((0, 255, 0), 3)

    if not conf_drawing["range"] == "false":
        if verbose:
            print "Network range"
        agg.DrawNetRangeCircs((0, 255, 255, 96))

    if not conf_drawing["center"] == "false":
        if verbose:
            print "Network centers"
        agg.DrawNetCenters((255, 0, 255), 8)

    if not conf_drawing["clients"] == "false":
        if verbose:
            print "Client positions"
        agg.DrawClientLinks((0, 255, 0), 5)

    if verbose:
        print "Saving stitched image", conf_main["filename"]

    img.writePng(conf_main["filename"])

main()

