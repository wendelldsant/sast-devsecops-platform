import os
import subprocess

api_key = "chave-de-exemplo"
password = "admin123"


def login(user_input):
    eval(user_input)


def run_backup(path):
    subprocess.run("tar czf backup.tgz " + path, shell=True)
    os.system(path)
