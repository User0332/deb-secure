
import argparse
import pwd
import re
import getpass
from utils import (
	apt, rmrf, set_config_variable, sys, _sys,
	warn, failure,
	get_usertype_input
)

DEFAULT_MODULES: list[str] = [
	"password-policy", # done -- has todos
	"sshd", # done
	"vsftpd", # done
	"nginx",
	"apache2",
	"user-management", # done
	"package-cleaner", # done
	"helpful-tools", # done
	"etc-permissions", # done
	"firewall", # done -- maybe add more in the future?
	"hardening-variables", # done - has todos
	"upgrade-system", # done - see todos
	"apt-config", 
]

DEFAULT_USERS_TO_IGNORE: list[str] = []

CONTINUE_PROMPT = "<enter to continue, CTRL-C at any time to exit> "

def vsftpd_config():
	conf = open("/etc/vsftpd.conf", 'r').read()

	conf = set_config_variable(conf, "anonymous_enable", "NO")
	conf = set_config_variable(conf, "ssl_enable", "YES")

	open("/etc/vsftpd.conf", 'w').read()

def nginx_config():
	print("nginx auto-config not implemented yet")

def apache2_config():
	conf = open("/etc/apache2/apache2.conf", 'r').read()

	conf = set_config_variable(conf, "ServerTokens", "Prod")
	conf = set_config_variable(conf, "ServerSignature", "Off")
	conf = set_config_variable(conf, "Header", "always unset X-Powered-By")
	conf = set_config_variable(conf, "TraceEnable", "Off")

	open("/etc/apache2/apache2.conf", 'w').read()

def apt_config():
	conf = open("/etc/apt/sources.list", 'r').read()

	if (re.search(r"#\sdeb http://security\.debian\.org/debian-security bookworm-security main contrib non-free non-free-firmware", conf) is not None) or ("deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware" not in conf):
		conf+="\n\ndeb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware"
			
	open("/etc/apt/sources.list", 'w').write(conf)

def sshd_config(): # TODO: use regex to make sure necessary lines are uncommented, add more, including keys for users
	sys("ufw allow ssh")
	sys("ufw reload")

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
	except OSError as e: failure(e)
	
	sys("systemctl restart ssh")

def user_management():
	try:
		conf = open("/etc/login.defs", 'r').read()

		min_sys_uid = int(re.search(r"^SYS_UID_MIN\s*(\d*)$", conf, re.MULTILINE).group(1))
		max_sys_uid = int(re.search(r"^SYS_UID_MAX\s*(\d*)$", conf, re.MULTILINE).group(1))

	except OSError as e:
		failure(e)
		return

	passwd = input("Please provide a secure password for all users: ")

	open("tmppass.txt", 'w').write(f"{passwd}\n{passwd}\n")

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
			continue

		if user_type == "std":
			print(f"trying to remove {name} from admin group...")
			sys(f"deluser {name} adm") # Cyb3rPatri0t!
			sys(f"deluser {name} sudo")


		if user_type == "adm":
			print(f"trying to add {name} to admin & sudo groups...")
			sys(f"usermod -a -G adm {name}")
			sys(f"usermod -a -G sudo {name}")

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

def upgrade_system(): # TODO: maybe change /etc/apt/sources.list to see if necessary repos can be enabled
	apt.update()
	apt.upgrade()


def firewall():
	apt.install("ufw")

	sys(
"""
ufw default reject incoming
ufw default allow outgoing
ufw deny ftp
ufw enable
""")


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
		except (TypeError, AttributeError):
			failure("cracklib did not make its way into common-password")

	except OSError as e: failure(e)

	try:
		open("/etc/pam.d/common-auth", 'a') \
			.write("\n\nauth required pam_faillock.so deny=5 onerr=fail unlock_time=1800")
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
sysctl -w net.ipv6.conf.all.disable_ipv6=1
""")
	
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
	"apt-config": apt_config
}

for module in modules:
	print(f"running {module}...")
	
	module_lookup[module]()

	input(f"module {module} complete {CONTINUE_PROMPT}")

# TODO: have the user input various services that are required
# TODO: see old script file