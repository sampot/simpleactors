# -*- coding: utf-8 -*-
"""
Various definitions used across different packages.
"""
from __future__ import absolute_import, print_function, unicode_literals

# activated engines

INSTALLED_ENGINES = [
    "ava.net.engine:TransportEngine",
    "ava.actor.engine:ActorEngine",
]


# tries to import definitions from the global settings.

try:
    from ava_settings import *
except ImportError:
    pass
