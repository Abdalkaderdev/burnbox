import json
import subprocess


def main():
    model = {"eval": True}
    print(json.dumps(model))
    subprocess.run(["git", "--version"], check=False)
