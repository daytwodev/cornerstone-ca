# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ricardo Arguello
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
