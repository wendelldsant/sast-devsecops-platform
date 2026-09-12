import subprocess

password = "senha_super_secreta_123"


def run_user_command(cmd):
    subprocess.run(cmd, shell=True)


def process_input(user_data):
    eval(user_data)