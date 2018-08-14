#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Source: https://www.mail-archive.com/ryu-devel%40lists.sourceforge.net/msg08519.html
# This is a wrapper script for running a Ryu controller under a debugger (e.g., PyCharm)
# Just execute this script, changing the name of the controller to debug if necessary

import sys
from ryu.cmd import manager


def main():
    sys.argv.append('sr_controller_test')  # Change this line to debug another controller
    sys.argv.append('--verbose')
    sys.argv.append('--enable-debugger')
    manager.main()


if __name__ == '__main__':
   main()
