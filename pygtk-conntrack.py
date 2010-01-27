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

from threading import Thread

from xml.etree.ElementTree import XML

import gtk
gtk.gdk.threads_init()
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

        self.model = gtk.ListStore( *([gobject.TYPE_STRING] * len(columns)) )

        self.list.set_model(self.model)

        for i in range(len(columns)):
            self.list.append_column(gtk.TreeViewColumn(columns[i].capitalize(),
                gtk.CellRendererText(), text=i))

        self.add(self.list)
        
        self.running = True

        def refresh_list():

            while self.running:
                self.model.clear()
                messages = self.cm.list()
                print messages
                for m in map(XML, messages):
                    self.model.append(parse_message(m))
                time.sleep(5)
        
        self.refresh_thread = Thread(target=refresh_list)
        self.refresh_thread.start()
        
        self.show_all()


    def _button_press(self, w, e):
        pass

    def destroy(self, w):
        self.running = False
        self.refresh_thread.join()
        gtk.main_quit()

def parse_message(e):

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

    return (id, state, proto, src, dst, sport, dport, packets_in, packets_out,
        bytes_in, bytes_out)


def main():
    w = MainWindow()
    print 'MainWindow initialized!'
    gtk.main()

if __name__ == "__main__":
    main()

