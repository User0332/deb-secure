import os
import secrets
import glob
import subprocess

def debug(msg: str):
	print(f"DEBUG => {msg}")

def failure(msg: str):
	debug(f"failed with {msg}")

class _apt:
	def __call__(self, cmd: str):
		try: return subprocess.call(["apt", *cmd.split()])
		except OSError as e: failure(e)

	def install(self, *packages: str): return [self(f"install {package}") for package in packages]

	def remove(self, *packages: str): return [self(f"remove {package}") for package in packages]

	def autoremove(self): return self("autoremove")
	
	def clean(self): return self("clean")

	def autoclean(self): return self("autoclean")

	def update(self): return self("update")

	def upgrade(self): return self("upgrade")

def _sys(cmd: str, **kwargs):
	try: return subprocess.call(cmd.split(), **kwargs)
	except OSError as e: failure(e)

def sys(cmds: str):
	return [_sys(cmd) for cmd in cmds.splitlines()]

def find(pattern: str, dir: str='/'):
	return glob.glob(f"{dir}**/{pattern}", recursive=True)

def rmrf(*paths: str):
	"""Runs `rm -rf` instead of using `os.remove`"""

	return [os.system(f"rm -rf {path}") for path in paths]

def get_usertype_input(user):
	while 1:
		input_type = input(f"User Type for {user}?\ns (std), a (adm), n (doesn't exist): ").lower()

		if input_type in ('s', "std", "standard", "reg", "regular"):
			return "std"
		elif input_type in ('a', "adm", "admin", "administrator"):
			return "adm"
		elif input_type in ('n', "none", "delete"):
			return "none"
		else:
			failure("[Invalid Input!]")

def generate_passwd(user: str):
	passwd = secrets.token_urlsafe(8)

	file = f"./{user}_pwd_delete-this.del.pls"
	
	with open(file, 'w') as f:
		f.write(f"{passwd}\n{passwd}\n")

	return passwd, file

apt = _apt()