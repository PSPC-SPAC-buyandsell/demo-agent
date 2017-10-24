#!/usr/bin/env python
import os
import sys
import argparse


if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.local")
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--role", help="agent role [trust_anchor|sri|the_org_book|bc_registrar]")
    args = parser.parse_args()
    print(args.role)
