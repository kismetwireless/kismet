# Kismetdb log processing utility module
#
# (c) 2018 Mike Kershaw / Dragorn
# Licensed under GPL2 or above

import datetime
import json
import struct
import sqlite3
import sys

MATCH_AND = 1
MATCH_OR = 2

class KismetLog:
    def __init__(self, dbfile):
        self.cursor = None

        self.matches = {}
        self.replacements = {}
        self.db = sqlite3.connect(dbfile)

    def filter_start_time(self, t, match = MATCH_AND):
        self.matches["first_time > :first_time"] = match
        self.replacements["first_time"] = t

    def filter_min_signal(self, s, match = MATCH_AND):
        self.matches["strongest_signal > :min_signal"] = match
        self.replacements["min_signal"] = s

    def get_next_device_row(self):
        if self.cursor is None:
            self.cursor = self.db.cursor()
            self.query = "SELECT device FROM devices "
            if len(self.matches) > 0:
                self.query = self.query + " WHERE "
                select = ""
                for m in self.matches:
                    if len(select) == 0:
                        select = m
                    else:
                        mt = "AND"
                        if self.matches[m] is MATCH_OR:
                            mt = "OR"
                        select = select + " " + mt + " " + m
                self.query = self.query + select
            print(self.query)
            self.cursor.execute(self.query, self.replacements)

        return self.cursor.fetchone()

    def get_next_device(self):
        obj = self.get_next_device_row()
        if obj is None:
            return None
        return json.loads(obj[0])
