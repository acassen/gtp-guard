# SPDX-License-Identifier: AGPL-3.0-or-later 
#
# Soft:        The main goal of gtp-guard is to provide robust and secure
#              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
#              widely used for data-plane in mobile core-network. gtp-guard
#              implements a set of 3 main frameworks:
#              A Proxy feature for data-plane tweaking, a Routing facility
#              to inter-connect and a Firewall feature for filtering,
#              rewriting and redirecting.
#
# Authors:     Alexandre Cassen, <acassen@gmail.com>
#
#              This program is free software; you can redistribute it and/or
#              modify it under the terms of the GNU Affero General Public
#              License Version 3.0 as published by the Free Software Foundation;
#              either version 3.0 of the License, or (at your option) any later
#              version.
#
# Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
#

"""Initialize app."""
from flask import Flask

def create_app():
    """Construct the core WAPP."""
    app = Flask(__name__)
    app.config.from_object(__name__)
    app.config['SECRET_KEY'] = '3e0bdeb3876a0fe59eaf4b71581c33b2'

    with app.app_context():
        # Import flask routes
        from . import routes

        return app
