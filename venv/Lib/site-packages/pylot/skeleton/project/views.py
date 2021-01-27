"""
Flask-Pilot views
"""

from flask import abort, request, redirect, url_for, jsonify
from flask_pilot import Pilot, route, flash_error, flash_success
from flask_pilot.views import error_view

Error = error_view()

class Index(Pilot):
    route_base = "/"

    def index(self):
        self.__(page_title="Hello Flask Pilot!")
        return self.render()

class Example(Pilot):
    def index(self):
        self.__(page_title="Example Page")
        flash_error("This is an error message set by flash_error() and called with show_flashed_message()")
        flash_success("This is a success message set by flash_error() and called with show_flashed_message()")
        return self.render()

