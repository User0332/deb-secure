import os
import re
import secrets
import glob
import subprocess
import threading
from sys import stdout
from typing import List

io_lock = threading.Lock()

thread_local = threading.local()

running_apt: str = None

def debug(msg: str):
	with io_lock: print(f"[{thread_local.current_module}] debug: {msg}")

def failure(msg: str):
	with io_lock: print(f"[{thread_local.current_module}] error: {msg}")

def warn(msg: str):
	with io_lock: print(f"[{thread_local.current_module}] warning: {msg}")

def comment_all_of_pattern(conf: str, pattern: str) -> str:
	for match in re.finditer(fr"^{pattern}$", conf, re.MULTILINE):
		conf = conf.replace(match.group(), f"# {match.group()}")

	return conf

def set_config_variable(conf: str, name: str, value: str, sep: str=' ') -> str:
	try:
		commented = re.search(fr"^\s*#\s*{name}.*$", conf, re.MULTILINE).group()

		return conf.replace(commented, f"{name}{sep}{value}")
	except AttributeError:
		try:
			var = re.search(fr"^\s*{name}.*$", conf, re.MULTILINE).group()

			return conf.replace(var, f"{name}{sep}{value}")
		except AttributeError:
			return conf+f"\n\n{name}{sep}{value}"

def bool_input_nolock(prompt: str) -> bool:
	while 1:
		inp = input(prompt).lower()

		if inp in ('y', "yes"): return True
		if inp in ('n', "no"): return False

		print("Invalid Input!")

def bool_input(prompt: str) -> bool:
	with io_lock: return bool_input_nolock(prompt)
		

def threaded_input(prompt: str) -> str:
	with io_lock:
		stdout.flush()

		print(f"[{thread_local.current_module}] {prompt}", end="", flush=True)

		return input()
		
class _apt:
	def __init__(self) -> None:
		self.lock = threading.Lock()

	def __call__(self, cmd: str):
			global running_apt
			try:
				running_apt = thread_local.current_module
				res = subprocess.call([f"apt {cmd}"], shell=True, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'), stdin=open(os.devnull, 'r'))
				running_apt = None

				return res
			except OSError as e: failure(e)

	def install(self, *packages: str): return self(f"install -y {' '.join(packages)}")

	def remove(self, *packages: str):
		package_str = ' '.join(packages)
		self(f"remove -y {package_str}")
		sys(f"dpkg --purge {package_str}")

	def autoremove(self): return self("autoremove -y")
	
	def clean(self): return self("clean")

	def autoclean(self): return self("autoclean")

	def update(self): return self("update")

	def upgrade(self): return self("upgrade -y")

def _sys(cmd: str, **kwargs):
	if "stdin" not in kwargs:
		kwargs["stdin"] = open(os.devnull, 'r')

	try: return subprocess.call(cmd, **kwargs, shell=True, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))
	except OSError as e: failure(e)

def sys(cmds: str):
	return [_sys(cmd) for cmd in cmds.splitlines() if cmd]

def find(pattern: str, dir: str='/'):
	return glob.glob(f"{dir}**/{pattern}", recursive=True)

def rmrf(*paths: str):
	"""Runs `rm -rf` instead of using `os.remove`"""

	return [subprocess.call(["rm", "-rf", path]) for path in paths]

def get_usertype_input(user):
	while 1:
		input_type = threaded_input(f"User Type for {user}?\ns (std), a (adm), n (doesn't exist) i (ignore): ").lower()

		if input_type in ('s', "std", "standard", "reg", "regular"):
			return "std"
		elif input_type in ('a', "adm", "admin", "administrator"):
			return "adm"
		elif input_type in ('n', "none", "delete"):
			return "none"
		elif input_type in ('i', 'ignore'):
			return "ignore"
		else:
			failure("[Invalid Input!]")

def generate_passwd(user: str):
	passwd = secrets.token_urlsafe(16)

	file = f"./{user}_pwd_delete-this.del.pls"
	
	with open(file, 'w') as f:
		f.write(f"{passwd}\n{passwd}\n")

	return passwd, file

def get_list_input_nolock(prompt: str) -> List[str]:
	inputs: List[str] = []

	stdout.flush()

	while 1:
		print(f"[{thread_local.current_module}] {prompt}", end="", flush=True)

		inp = input()

		if not inp: break

		inputs.append(inp)

	return inputs

def get_list_input(prompt: str) -> List[str]:
	with io_lock: return get_list_input_nolock(prompt)

def removeprefix_compat(string: str, prefix: str):
	if string.startswith(prefix):
		return string[len(prefix):]
	
	return string

apt = _apt()