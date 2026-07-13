import os
env = os.environ.get("DJANGO_ENV", "local")
if env == "local":
    from .local import *
else:
    from .base import *
