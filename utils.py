import re
import secrets
import glob
import subprocess

def debug(msg: str):
	print(f"debug: {msg}")

def failure(msg: str):
	print(f"error: failed on module with {msg}")

def warn(msg: str):
	print(f"warning: module warned with {msg}")

def comment_all_of_pattern(conf: str, pattern: str) -> str:
	for match in re.finditer(fr"^{pattern}$", conf, re.MULTILINE):
		conf = conf.replace(match.group(), f"# {match.group()}")

	return conf

def set_config_variable(conf: str, name: str, value: str, sep: str=' ') -> str:
	try:
		commented = re.search(fr"^#\s{name}.*$", conf, re.MULTILINE).group()

		return conf.replace(commented, f"{name}{sep}{value}")
	except AttributeError:
		try:
			var = re.search(fr"^{name}.*$", conf, re.MULTILINE).group()

			return conf.replace(var, f"{name}{sep}{value}")
		except AttributeError:
			return conf+f"\n\n{name}{sep}{value}"
		
def bool_input(prompt: str) -> bool:
	while 1:
		inp = input(prompt).lower()

		if inp in ('y', "yes"): return True
		if inp in ('n', "no"): return False

		print("Invalid Input!")
		
class _apt:
	def __call__(self, cmd: str):
		try: return subprocess.call(["apt", *cmd.split()])
		except OSError as e: failure(e)

	def install(self, *packages: str): return self(f"install -y {' '.join(packages)}")

	def remove(self, *packages: str): return self(f"remove -y {' '.join(packages)}")

	def autoremove(self): return self("autoremove -y")
	
	def clean(self): return self("clean")

	def autoclean(self): return self("autoclean")

	def update(self): return self("update")

	def upgrade(self): return self("upgrade -y")

def _sys(cmd: str, **kwargs):
	try: return subprocess.call(cmd.split(), **kwargs)
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
		input_type = input(f"User Type for {user}?\ns (std), a (adm), n (doesn't exist) i (ignore): ").lower()

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

def removeprefix_compat(string: str, prefix: str):
	if string.startswith(prefix):
		return string[len(prefix):]
	
	return string

apt = _apt()