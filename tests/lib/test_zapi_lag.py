# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Aviz Networks
import frrtest


class TestZapiLag(frrtest.TestMultiOut):
    program = "./test_zapi_lag"


TestZapiLag.onesimple("micro-BFD ZAPI message checks passed.")
