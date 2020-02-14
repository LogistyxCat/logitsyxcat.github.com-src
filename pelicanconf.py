#!/usr/bin/env python
# -*- coding: utf-8 -*- #
from __future__ import unicode_literals

AUTHOR = 'Riley'
SITENAME = 'LogistyxCat'
SITEURL = 'https://logistyxcat.github.io'

# Uncomment following line if you want document-relative URLs when developing
RELATIVE_URLS = True

# Define some project paths that have special meanings in Pelican
PATH = 'content'
PAGE_PATHS = ['pages']
STATIC_PATHS = ['images']


TIMEZONE = 'America/Los_Angeles'

DEFAULT_LANG = 'en'

# Feed generation is usually not desired when developing
FEED_ALL_ATOM = None
CATEGORY_FEED_ATOM = None
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = None
AUTHOR_FEED_RSS = None

# Theme
THEME = "themes/pure"
PROFILE_IMAGE_URL = '/images/cat.jpg'
COVER_IMG_URL = '/images/sidebar.jpg' 
TAGLINE = "Blog of a security student."

# Blogroll
LINKS = (('Pelican', 'http://getpelican.com/'),
         ('Python.org', 'http://python.org/'),
         ('Jinja2', 'http://jinja.pocoo.org/'),
         ('You can modify those links in your config file', '#'),)
         
# Fixed menu entries
MENUITEMS = [
        ('Archives', '/archives.html')
]

# Files to ignore
IGNORE_FILES = [
        ".\changeme.md"
]

# Social widget
SOCIAL = (('twitter', 'https://twitter.com/LogistyxCat'),
          ('github', 'https://github.com/LogistyxCat'),)
         
DEFAULT_PAGINATION = False
