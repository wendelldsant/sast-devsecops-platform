import os


def process_user_command(cmd):
    eval(cmd)


def run_system_command(command):
    os.system(command)


def get_user_input():
    user_data = input("Digite um valor: ")
    eval(user_data)


def safe_example(value):
    value = int(value)  # sanitização: conversão explícita de tipo
    eval(value)