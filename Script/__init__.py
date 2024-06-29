import asyncio, binascii, chardet, gzip
import hashlib, ipaddress, io
import os
import re, random, sys, ssl, socket, tldextract
import whois

from base64 import b64decode, b64encode
from bs4 import BeautifulSoup
from colorama import init as cinit, Fore
from docx import Document
from docx.shared import Inches
from datetime import datetime
from dns import resolver
from email.utils import formatdate
from json import loads, load, dumps, dump
from jose.jwt import encode as jwt_encode, decode as jwt_decode
from http import HTTPStatus
from html import unescape
from nslookup import Nslookup
from sanic import Sanic
from sanic.response import json as r_json, text, redirect, file, html, json, HTTPResponse
from sanic.exceptions import (
    InvalidUsage, Unauthorized, Forbidden, NotFound, MethodNotAllowed, URLBuildError, ServerError, ServiceUnavailable
)
from struct import unpack
from socket import inet_aton, gethostbyname, gaierror, create_connection
from time import time, sleep, strftime
from urllib.parse import unquote, urlparse, quote
from pyDes import des, CBC, PAD_PKCS5
from urllib3 import disable_warnings
