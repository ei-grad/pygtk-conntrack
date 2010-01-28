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

        columns = ('id', 'state', 'protocol', 'source', 'destination',
            'source port', 'destination port', 'packets in', 'packets out',
            'bytes in', 'bytes out')

        self.model = gtk.ListStore(
            gobject.TYPE_UINT64,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_INT,
            gobject.TYPE_INT,
            gobject.TYPE_UINT64,
            gobject.TYPE_UINT64,
            gobject.TYPE_UINT64,
            gobject.TYPE_UINT64
        )

        self.list.set_model(self.model)

        for i in range(len(columns)):
            column = gtk.TreeViewColumn(columns[i].capitalize(),
                gtk.CellRendererText(), text=i)
            column.set_sort_column_id(i)
            self.list.append_column(column)

        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
        sw.add(self.list)

        self.add(sw)
        
        self.running = True
        self.update_interval = 1000
        self.messages = {}

        def refresh_list():

            try:
                messages = self.cm.list()
            except:
                messages = []

            messages = map(parse_message, messages)
            new_ids = [ i[0] for i in messages ]

            for i in self.messages.keys():
                if i not in new_ids:
                    self.model.remove(self.messages.pop(i))
            
            old_ids = self.messages.keys()
            for m in messages:
                if m[0] not in old_ids:
                    self.messages[m[0]] = self.model.append(m)
                else:
                    fuck = []
                    for i in zip(range(len(m)), m):
                        fuck.extend(i)
                    self.model.set(self.messages[m[0]], *fuck)

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

    indep = filter(lambda x: x.get('direction') == "independent", e.getiterator('meta'))[0]
    orig = filter(lambda x: x.get('direction') == "original", e.getiterator('meta'))[0]
    reply = filter(lambda x: x.get('direction') == "reply", e.getiterator('meta'))[0]
    
    id = indep.getiterator('id')[0].text
    try:
        state = indep.getiterator('state')[0].text
    except:
        state = 'UNKNOWN'
    proto = orig.getiterator('layer4')[0].get('protoname')
    src = orig.getiterator('layer3')[0].getiterator('src')[0].text
    dst = orig.getiterator('layer3')[0].getiterator('dst')[0].text

    if proto == 'udp' or proto == 'tcp':
        sport = orig.getiterator('layer4')[0].getiterator('sport')[0].text
        dport = orig.getiterator('layer4')[0].getiterator('dport')[0].text
    else:
        sport = 0
        dport = 0

    packets_in = orig.getiterator('counters')[0].getiterator('packets')[0].text
    packets_out = reply.getiterator('counters')[0].getiterator('packets')[0].text
    bytes_in = orig.getiterator('counters')[0].getiterator('bytes')[0].text
    bytes_out = reply.getiterator('counters')[0].getiterator('bytes')[0].text

    return (int(id), state, proto, src, dst, int(sport), int(dport),
        int(packets_in), int(packets_out), int(bytes_in), int(bytes_out))


def main():
    w = MainWindow()
    gtk.main()

if __name__ == "__main__":
    main()

