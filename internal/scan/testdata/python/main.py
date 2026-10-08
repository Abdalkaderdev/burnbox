import base64
import os
import subprocess

exec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk=").decode())
print(eval("1 + 1"))
name = "world"
subprocess.run("echo " + name, shell=True)
print("path only:", os.path.expanduser("~/.aws/credentials"))
