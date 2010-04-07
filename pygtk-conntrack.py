#!/usr/bin/env python
#
# Tool to display and manipulate by network connections, tracked by conntrack.
#
# Copyright (C) 2010 Andrew Grigorev <andrew@ei-grad.ru>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import sys
import time

from xml.etree.ElementTree import XML

import gtk
import gobject

from Conntrack import ConnectionManager


class MainWindow(gtk.Window):
    """GTK based Conntrack network connection manager."""

    def __init__(self, parent=None):
       
        gtk.Window.__init__(self)
        try:
            self.set_screen(parent.get_screen())
        except AttributeError:
            self.connect('destroy', self.destroy)

        self.set_default_size(500,600)
        self.set_title("PyGTKConntrack")

        self.cm = ConnectionManager()

        self.list = gtk.TreeView()
        self.list.connect('button-press-event', self._button_press)

        self.columns = ('id', 'state', 'proto3', 'proto4', 'src', 'dst',
            'sport', 'dport', 'packets_in', 'packets_out',
            'bytes_in', 'bytes_out')

        self.model = gtk.ListStore(
            gobject.TYPE_UINT64,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_UINT64,
            gobject.TYPE_UINT64,
            gobject.TYPE_UINT64,
            gobject.TYPE_UINT64,
            gobject.TYPE_UINT64,
            gobject.TYPE_UINT64
        )

        self.list.set_model(self.model)

        for i, title in enumerate(self.columns):
            column = gtk.TreeViewColumn(title.capitalize(),
                gtk.CellRendererText(), text=i)
            column.set_sort_column_id(i)
            self.list.append_column(column)

        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
        sw.add(self.list)

        self.add(sw)
        
        self.running = True
        self.update_interval = 5000
        self.messages = {}

        def refresh_list():

            try:
                mess_list = self.cm.list()
            except:
                mess_list = []
            
            new_messages = {}
            for i in mess_list:
                m = parse_message(i)
                if 'proto4' not in m:
                    m['proto4'] = ""
                if 'state' not in m:
                    m['state'] = "UNKNOWN"
                if 'sport' not in m:
                    m['sport'] = 0
                if 'dport' not in m:
                    m['dport'] = 0
                new_messages[m['id']] = m

            old_ids = set(self.messages.keys())
            new_ids = set(new_messages.keys())

            for id in old_ids.difference(new_ids):
                self.model.remove(self.messages.pop(id))
            
            for id in new_ids.difference(old_ids):
                msg = new_messages[id]
                mesg = [ msg[col] for col in self.columns ]
                self.messages[id] = self.model.append(mesg)
            
            for id in new_ids.intersection(old_ids):
                m = new_messages[id]
                mesg = []
                for i in 'state', 'bytes_in', 'bytes_out', 'packets_in', 'packets_out':
                    mesg.extend((self.columns.index(i), m[i]))
                self.model.set(self.messages[id], *mesg)

            return True
        
        refresh_list()
        gtk.timeout_id = gobject.timeout_add(self.update_interval,
                                                refresh_list)
        
        self.show_all()


    def _button_press(self, w, e):
        pass

    def destroy(self, w):
        gtk.main_quit()
        sys.exit(0)

def parse_message(e):
    
    e = XML(e)

    ret = {}

    for i in e:
        direction = i.get('direction')
        if direction == 'original':
            for j in i:
                if j.tag == 'layer4':
                    ret['proto4'] = j.get('protoname', '')
                    for k in j:
                        if k.tag == 'sport': ret['sport'] = int(k.text)
                        elif k.tag == 'dport': ret['dport'] = int(k.text)
                elif j.tag == 'layer3':
                    ret['proto3'] = j.get('protoname')
                    for k in j:
                        if k.tag == 'src': ret['src'] = k.text
                        elif k.tag == 'dst': ret['dst'] = k.text
                elif j.tag == 'counters':
                    for k in j:
                        if k.tag == 'packets': ret['packets_out'] = int(k.text)
                        elif k.tag == 'bytes': ret['bytes_out'] = int(k.text)
        elif direction == 'reply':
            for j in i:
                for k in j:
                    if k.tag == 'packets': ret['packets_in'] = int(k.text)
                    elif k.tag == 'bytes': ret['bytes_in'] = int(k.text)
        elif direction == 'independent':
            for j in i:
                if j.tag == 'id': ret['id'] = int(j.text)
                elif j.tag == 'state': ret['state'] = j.text

    return ret

def main():
    w = MainWindow()
    gtk.main()

if __name__ == "__main__":
    main()

