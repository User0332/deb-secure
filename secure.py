
import argparse
import glob
import pwd
import re
import getpass
import subprocess
from utils import (
	apt, bool_input, rmrf, set_config_variable, sys, _sys,
	warn, failure,
	get_usertype_input
)

DEFAULT_MODULES: list[str] = [
	"password-policy", # done -- has todos
	"firewall", # done -- maybe add more in the future?
	"sshd", # done
	"vsftpd", # done
	"nginx",
	"apache2",
	"user-management", # done
	"package-cleaner", # done
	"helpful-tools", # done
	"etc-permissions", # done
	"hardening-variables", # done - has todos
	"upgrade-system", # done - see todos
	"apt-config", # done
	"prohibited-files", # done
	"service_management", # done, see todos
]

REMOVE_IF_NOT_CRITICAL: dict[str, str] = {
	"nginx": "nginx",
	"apache2": "apache2",
	"vsftpd": "vsftpd",
	"ssh": "openssh-server",
	"pure-ftpd": "pure-ftpd"
}

CONTINUE_PROMPT = "<enter to continue, CTRL-C at any time to exit> "

class Log:
	removed_files: list[str] = []
	attempted_remove_packages: list[str] = []
	removed_users: list[str] = []
	std_users: list[str] = []
	adm_users: list[str] = []
	tools_installed: list[str] = []
	services_stopped: list [str] = []
	user_passwd: str = ""
	vsftpd_changes: str = ""
	sshd_changes: str = ""
	nginx_changes: str = ""
	apt_changes: str = ""
	apache2_changes: str = ""
	passwd_changes: str = ""
	hardening_variable_changes: str = ""
	etc_permissions_set: str = ""
	firewall_rules: str = ""

def service_management(): # TODO: start stopped critical services
	services = input("Enter a comma-separated list of critical services (no spaces)").split(',')

	running_services = [line.removeprefix(" [ + ]").split() for line in subprocess.check_output(["service", "--status-all"]).splitlines() if line.startswith(" [ + ]")]

	for servicename in REMOVE_IF_NOT_CRITICAL:
		if servicename in running_services and servicename not in services:
			if bool_input(f"Non-critical service {servicename} found, stop? "):
				sys(f"systemctl stop {servicename}")

				Log.services_stopped.append(servicename)

	for servicename, packagename in REMOVE_IF_NOT_CRITICAL.items():
		if servicename not in services:
			if bool_input(f"Non-critical service package {packagename} found, remove? "):
				apt.remove(packagename)

				Log.attempted_remove_packages.append(packagename)

def prohibited_files():
	prohibited_files = (
		glob.glob("*.mp3", root_dir="/home", recursive=True) + 
		glob.glob("*.mp4", root_dir="/home", recursive=True)
	)

	print("found the following mp3 and mp4 files in /home (to remove, provide comma-sep list or 'all'): ")

	for i, mp3 in enumerate(prohibited_files):
		print(f"{i}: {mp3}")

	remove = input("choice: ")

	if remove == "all":
		rmrf(prohibited_files)
		Log.removed_files = prohibited_files
	else:
		remove_idxs = [int(idx) for idx in remove.split(',')]

		for idx in remove_idxs:
			rmrf(prohibited_files[idx])
			Log.removed_files.append(prohibited_files[idx])

	

def vsftpd_config():
	sys("ufw allow ftp")
	sys("ufw reload")

	conf = open("/etc/vsftpd.conf", 'r').read()

	conf = set_config_variable(conf, "anonymous_enable", "NO")
	conf = set_config_variable(conf, "ssl_enable", "YES")

	open("/etc/vsftpd.conf", 'w').write(conf)

	Log.vsftpd_changes+="anonymous_enable=NO,ssl_enable=YES,"
	Log.firewall_rules+="allow ftp,"

def nginx_config():
	print("nginx auto-config not implemented yet")

def apache2_config():
	conf = open("/etc/apache2/apache2.conf", 'r').read()

	conf = set_config_variable(conf, "ServerTokens", "Prod")
	conf = set_config_variable(conf, "ServerSignature", "Off")
	conf = set_config_variable(conf, "Header", "always unset X-Powered-By")
	conf = set_config_variable(conf, "TraceEnable", "Off")

	open("/etc/apache2/apache2.conf", 'w').write(conf)

	Log.apache2_changes+="ServerTokens=Prod,ServerSignature=Off,Header=always unset X-Powered-By,TraceEnable=Off,"

def apt_config():
	conf = open("/etc/apt/sources.list", 'r').read()

	if (re.search(r"#\sdeb http://security\.debian\.org/debian-security bookworm-security main contrib non-free non-free-firmware", conf) is not None) or ("deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware" not in conf):
		conf+="\n\ndeb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware"
			
		Log.apt_changes+="added source deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware,"

	open("/etc/apt/sources.list", 'w').write(conf)

def sshd_config(): # TODO: use regex to make sure necessary lines are uncommented, add more, including keys for users
	sys("ufw allow ssh")
	sys("ufw reload")

	Log.firewall_rules+="allow ssh,"

	try:
		conf = open("/etc/ssh/sshd_config", 'r').read()

		conf = set_config_variable(conf, "PermitRootLogin", "no")
		conf = set_config_variable(conf, "PermitEmptyPasswords", "no")
		conf = set_config_variable(conf, "PermitTunnel", "no")
		conf = set_config_variable(conf, "PasswordAuthentication", "no")
		conf = set_config_variable(conf, "X11Forwarding", "no")
		conf = set_config_variable(conf, "AllowTcpForwarding", "no")
		conf = set_config_variable(conf, "AllowAgentForwarding", "no")
		conf = set_config_variable(conf, "DebianBanner", "no")
		conf = set_config_variable(conf, "UsePAM", "yes")
		conf = set_config_variable(conf, "IgnoreRhosts", "yes")
		conf = set_config_variable(conf, "MaxAuthTries", '5')
		conf = set_config_variable(conf, "Ciphers", "aes128-ctr,aes192-ctr,aes256-ctr")
		conf = set_config_variable(conf, "ClientAliveInterval", "900")
		conf = set_config_variable(conf, "ClientAliveCountMax", '0')

		open("/etc/ssh/sshd_config", 'w').write(conf)

		Log.sshd_changes+=(
			"PermitRootLogin=no,PermitEmptyPasswords=no,PermitTunnel=no,PasswordAuthentication=no,X11Forwarding=no,AllowTcpForwarding=no" 
			"AllowAgentForwarding=no,DebianBanner=no,UsePAM=yes,IgnoreRhosts=yes,MaxAuthTries=5,Ciphers=aes128-ctr,aes192-ctr,aes256-ctr,ClientAliveInterval=900"
			"ClientAliveCountMax=0,"
		)

	except OSError as e: failure(e)
	
	sys("systemctl restart ssh")

def user_management(): # TODO: uncomment SYS_UID_MIN/MAX
	try:
		conf = open("/etc/login.defs", 'r').read()

		min_sys_uid = int(re.search(r"^SYS_UID_MIN\s*(\d*)$", conf, re.MULTILINE).group(1))
		max_sys_uid = int(re.search(r"^SYS_UID_MAX\s*(\d*)$", conf, re.MULTILINE).group(1))

	except OSError as e:
		failure(e)
		return
	except AttributeError: # sys_uid min and max were commented
		try: min_uid = int(re.search(r"^UID_MIN\s*(\d*)$", conf, re.MULTILINE).group(1))
		except AttributeError: min_uid = 1000 # uid_min was commented

		min_sys_uid = 101
		max_sys_uid = min_uid-1

	passwd = input("Please provide a secure password for all users: ")

	open("tmppass.txt", 'w').write(f"{passwd}\n{passwd}\n")

	Log.user_passwd = passwd

	for user in pwd.getpwall():
		name = user.pw_name

		if min_sys_uid <= user.pw_uid <= max_sys_uid:
			print(f"ignoring known system user {name} by default, continuing")
			continue

		if name == getpass.getuser():
			print(f"ignoring user {name} (self), continuing")
			continue

		user_type = get_usertype_input(name)

		if user_type == "ignore": continue

		if user_type == "none":
			print(f"trying to delete {name}...")
			sys(f"deluser {name}")

			Log.removed_users.append(name)
			continue

		if user_type == "std":
			print(f"trying to remove {name} from admin group...")
			sys(f"deluser {name} adm") # Cyb3rPatri0t!
			sys(f"deluser {name} sudo")

			Log.std_users.append(name)


		if user_type == "adm":
			print(f"trying to add {name} to admin & sudo groups...")
			sys(f"usermod -a -G adm {name}")
			sys(f"usermod -a -G sudo {name}")

			Log.adm_users.append(name)

		print(f"changing password for {name} to {passwd}...")

		_sys(
			f"passwd {name}",
			stdin=open("tmppass.txt")
		)

	rmrf("tmppass.txt")

def helpful_tools():
	apt.install(
		"net-tools",
		"chkrootkit",
		"rkhunter",
		"lynis",
		"stacer",
		"gufw"
	)

	Log.tools_installed.extend(["net-tools", "chkrootkit", "rkhunter", "lynis", "stacer", "gufw"])


def package_cleaner(): # remove bad packages
	apt.remove(
		"samba-common", "icecast2",
		"zangband", "libpcap-dev", "ophcrack",
		"hydra", "deluge", "wireshark",
		"utorrent", "nmap", "avernum",
		"manaplus", "ettercap", "ettercap-graphical", "zenmap",
		"freeciv", "kismet-plugins",
		"libnet-akismet-perl",
		"ruby-akismet", "gameconqueror", "telnet"
	)

	apt.autoremove()

	Log.attempted_remove_packages.extend(
		[
			"samba-common", "icecast2",
			"zangband", "libpcap-dev", "ophcrack",
			"hydra", "deluge", "wireshark",
			"utorrent", "nmap", "avernum",
			"manaplus", "ettercap", "ettercap-graphical", "zenmap",
			"freeciv", "kismet-plugins",
			"libnet-akismet-perl",
			"ruby-akismet", "gameconqueror", "telnet"
		]
	)

def upgrade_system(): # TODO: maybe change /etc/apt/sources.list to see if necessary repos can be enabled
	apt.update()
	apt.upgrade()


def firewall():
	apt.install("ufw")

	sys(
"""
ufw default reject incoming
ufw default allow outgoing
ufw enable
""")
	
	Log.firewall_rules+="default reject incoming,default allow outgoing"


def etc_permissions(): # a bunch of files have 644 perms but that's just 755 without execute access -- etc shouldn't have executables anyway
	sys("chown -R root:root /etc")
	sys("chmod -R 755 /etc")


	sys("chown root:shadow /etc/gshadow")
	sys("chown root:shadow /etc/gshadow-")

	sys("chmod 640 /etc/gshadow")
	sys("chmod 640 /etc/gshadow-")

	sys("chown root:shadow /etc/shadow")
	sys("chown root:shadow /etc/shadow-")

	sys("chmod 640 /etc/shadow")
	sys("chmod 640 /etc/shadow-")


	sys("chmod 440 /etc/sudoers")
	sys("chmod 444 /etc/machine-id")

	Log.etc_permissions_set+="/etc - [recursive] 755 root:root,/etc/shadow* - 640 root:shadow,/etc/gshadow* - 640 root:shadow,/etc/sudoers - 440 root:root,/etc/machine-id - 440 root:root,"


def password_policy():
	apt.install("libpam-cracklib")

	try:
		conf = open("/etc/login.defs", 'r').read()

		max_days = re.search(r"^PASS_MAX_DAYS.*$", conf, re.MULTILINE).group()
		min_days = re.search(r"^PASS_MIN_DAYS.*$", conf, re.MULTILINE).group()
		warn_days = re.search(r"^PASS_WARN_AGE.*$", conf, re.MULTILINE).group()
		encrypt_method = re.search(r"^ENCRYPT_METHOD.*$", conf, re.MULTILINE).group()

		conf = conf.replace(max_days, "PASS_MAX_DAYS\t90")
		conf = conf.replace(min_days, "PASS_MIN_DAYS\t7")
		conf = conf.replace(warn_days, "PASS_WARN_AGE\t14")
		conf = conf.replace(encrypt_method, "ENCRYPT_METHOD SHA512")

		open("/etc/login.defs", 'w').write(conf)

		Log.passwd_changes+="login.defs: max_days=90,min_days=7,warn_age=14,encrypt_method=sha512,"
	except OSError as e: failure(e)

	## TODO: ENSURE THAT THESE PAM CONFIGS ARE CORRECT

	try:
		conf = open("/etc/pam.d/common-password", 'r').read()

		try:
			pam_unix = re.search(r"pam_unix\.so.*$", conf, re.MULTILINE).group()
			cracklib = re.search(r"pam_cracklib\.so.*$", conf, re.MULTILINE).group()

			conf = conf.replace(pam_unix, f"{pam_unix} remember=5 minlen=8")
			conf = conf.replace(cracklib, f"{cracklib} ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1")

			open("/etc/pam.d/common-password", 'w').write(conf)

			Log.passwd_changes+="common-password: ... pam_unix.so ... remember=5 minlen=8, ... pam_cracklib.so ... ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1,"
		except (TypeError, AttributeError):
			failure("cracklib did not make its way into common-password")

	except OSError as e: failure(e)

	try:
		open("/etc/pam.d/common-auth", 'a') \
			.write("\n\nauth required pam_faillock.so deny=5 onerr=fail unlock_time=1800")
		
		data = open("/etc/pam.d/common-auth", 'r').read()

		open("/etc/pam.d/common-auth", 'w').write(data.replace("nullok", ''))
		
		Log.passwd_changes+="common-auth: auth required pam_faillock.so deny=5 onerr=fail unlock_time=1800,removed nullok if present,"
	except OSError as e: failure(e)

def hardening_variables():
	sys(
"""
sysctl -w  dev.tty.ldisc_autoload=0
sysctl -w  fs.protected_fifos=2
sysctl -w  fs.protected_hardlinks=1
sysctl -w  fs.protected_regular=2
sysctl -w  fs.protected_symlinks=1
sysctl -w  fs.suid_dumpable=0
sysctl -w  kernel.core_uses_pid=1
sysctl -w  kernel.ctrl-alt-del=0
sysctl -w  kernel.dmesg_restrict=1
sysctl -w  kernel.kptr_restrict=2
sysctl -w  kernel.modules_disabled=1
sysctl -w  kernel.perf_event_paranoid=3
sysctl -w  kernel.randomize_va_space=2
sysctl -w  kernel.sysrq=0
sysctl -w  kernel.unprivileged_bpf_disabled=1
sysctl -w  kernel.yama.ptrace_scope=1
sysctl -w  net.core.bpf_jit_harden=2
sysctl -w  net.ipv4.conf.all.accept_redirects=0
sysctl -w  net.ipv4.conf.all.accept_source_route=0
sysctl -w  net.ipv4.conf.all.bootp_relay=0
sysctl -w  net.ipv4.conf.all.forwarding=0
sysctl -w  net.ipv4.conf.all.log_martians=1
sysctl -w  net.ipv4.conf.all.mc_forwarding=0
sysctl -w  net.ipv4.conf.all.proxy_arp=0
sysctl -w  net.ipv4.conf.all.rp_filter=1
sysctl -w  net.ipv4.conf.all.send_redirects=0
sysctl -w  net.ipv4.conf.default.accept_redirects=0
sysctl -w  net.ipv4.conf.default.accept_source_route=0
sysctl -w  net.ipv4.conf.default.log_martians=1
sysctl -w  net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w  net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w  net.ipv4.tcp_syncookies=1
sysctl -w  net.ipv4.tcp_timestamps=0
sysctl -w  net.ipv6.conf.all.accept_redirects=0
sysctl -w  net.ipv6.conf.all.accept_source_route=0
sysctl -w  net.ipv6.conf.default.accept_redirects=0
sysctl -w  net.ipv6.conf.default.accept_source_route=0
sysctl -w  net.ipv6.conf.all.disable_ipv6=1
""")
	
	Log.hardening_variable_changes+="""
dev.tty.ldisc_autoload=0
fs.protected_fifos=2
fs.protected_hardlinks=1
fs.protected_regular=2
fs.protected_symlinks=1
fs.suid_dumpable=0
kernel.core_uses_pid=1
kernel.ctrl-alt-del=0
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.modules_disabled=1
kernel.perf_event_paranoid=3
kernel.randomize_va_space=2
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
kernel.yama.ptrace_scope=1
net.core.bpf_jit_harden=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.bootp_relay=0
net.ipv4.conf.all.forwarding=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.mc_forwarding=0
net.ipv4.conf.all.proxy_arp=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_timestamps=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.all.disable_ipv6=1
"""

	# for some reason net.ipv4.ip_forwarding=0 errors all the time (TODO: look into this) so we'll write it in the config for now

	try:
		conf = open("/etc/sysctl.conf", 'r').read()

		try:
			ip_forward = re.search(r"^net\.ipv4\.ip_forwarding=.*$", conf, re.MULTILINE).group()

			conf = conf.replace(ip_forward, "net.ipv4.ip_forwarding=0")

		except AttributeError:
			warn("net.ipv4.ip_forwarding variable not found in sysctl.conf")
			conf+="\n\net.ipv4.ip_forwarding=0"

		open("/etc/sysctl.conf", 'w').write(conf)

		Log.hardening_variable_changes+="net.ipv4.ip_forwarding=0\n"

	except OSError as e: failure(e)


parser = argparse.ArgumentParser(description="Secure Debian-Based Systems", prog="secure")

flaggroup = parser.add_mutually_exclusive_group(required=True)
flaggroup.add_argument("-i", "--include", nargs='*', default=[])
flaggroup.add_argument("-e", "--exclude", nargs='*', default=[])

args = parser.parse_args()

if args.include:
	modules: list[str] = args.include

	for module in modules:
		if module not in DEFAULT_MODULES:
			print(f"error: module '{module}' not available")
			exit(1)
else:
	modules = [item for item in DEFAULT_MODULES if item not in args.exclude]

	for module in args.exclude:
		if module not in DEFAULT_MODULES:
			print(f"warning: module '{module}' doesn't exist, skipping exclude for '{module}'")

input(f"\n\ncontinuing with the following modules: {' '.join(modules)} {CONTINUE_PROMPT}")

module_lookup = {
	"password-policy": password_policy,
	"package-cleaner": package_cleaner,
	"helpful-tools": helpful_tools,
	"upgrade-system": upgrade_system,
	"hardening-variables": hardening_variables,
	"etc-permissions": etc_permissions,
	"firewall": firewall,
	"sshd": sshd_config,
	"vsftpd": vsftpd_config,
	"nginx": nginx_config,
	"apache2": apache2_config,
	"user-management": user_management,
	"apt-config": apt_config,
	"prohibited-files": prohibited_files,
	"service-management": service_management
}

for module in modules:
	print(f"running {module}...")
	
	module_lookup[module]()

	input(f"module {module} complete {CONTINUE_PROMPT}")

with open("./secure.log", 'w') as f:
	f.write(f"removed files: {', '.join(Log.removed_files)}\n")
	f.write(f"attempted to remove packages: {', '.join(Log.attempted_remove_packages)}\n")
	f.write(f"services stopped: {', '.join(Log.services_stopped)}")
	f.write(f"removed users: {', '.join(Log.removed_users)}\n")
	f.write(f"std users: {', '.join(Log.std_users)}\n")
	f.write(f"adm users: {', '.join(Log.adm_users)}\n")
	f.write(f"user passwd: {Log.user_passwd}\n")
	f.write(f"tools installed: {', '.join(Log.tools_installed)}\n")
	f.write(f"vsftpd changes: {Log.vsftpd_changes}\n")
	f.write(f"sshd changes: {Log.sshd_changes}\n")
	f.write(f"nginx changes: {Log.nginx_changes}\n")
	f.write(f"apt changes: {Log.apt_changes}\n")
	f.write(f"apache2 changes: {Log.apache2_changes}\n")
	f.write(f"password policy changes: {Log.passwd_changes}\n")
	f.write(f"etc permissions set: {Log.etc_permissions_set}\n")
	f.write(f"firewall rules set: {Log.firewall_rules}\n")
	f.write(f"hardening variables set: {Log.hardening_variable_changes}\n")

# TODO: have the user input various services that are required
# TODO: see old script file