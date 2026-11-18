# Planted defect for the ruff self-test (#199). Expected: S602 and S324.
import hashlib
import subprocess


def run(cmd):
    subprocess.run(cmd, shell=True)
    return hashlib.md5(cmd.encode()).hexdigest()
