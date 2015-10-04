# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, unicode_literals

from gevent import monkey
monkey.patch_all()

import logging

logging.basicConfig(level=logging.DEBUG)

# prevent no handler warning
try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass


logger = logging.getLogger("ava")

from ava.core.agent import start_agent


if __name__ == '__main__':
    start_agent()
