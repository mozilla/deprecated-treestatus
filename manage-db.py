#!/usr/bin/env python
import os
import site
my_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
site.addsitedir(os.path.join(my_dir, "vendor/lib/python"))
from migrate.versioning.shell import main

if __name__ == '__main__':
    main()
