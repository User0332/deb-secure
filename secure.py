import argparse
import glob
import pwd
import fcntl
import grp
import signal
import struct
import re
import os
import getpass
import subprocess
import threading
import time
from typing import Dict, List
from utils import (
	apt, bool_input, bool_input_nolock, get_list_input, get_list_input_nolock, removeprefix_compat, 
	rmrf, set_config_variable, sys, _sys,
	warn, failure, threaded_input,
)
import utils

FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
FS_IMMUTABLE_FL = 0x00000010
FS_INDEX_FL = 0x00001000
FS_EXTENT_FL = 0x00080000

DEFAULT_MODULES: List[str] = [
	"apt-config", # done, this is first to ensure that all following modules can install the necessary packages
	"ctrl-alt-del", # done
	"gsettings-and-gdm-config", # done
	"lightdm", # done
	"password-policy", # done -- has todos
	"firewall", # done -- maybe add more in the future?
	"sshd", # done
	"vsftpd", # done
	"nginx",
	"apache2",
	"user-management", # done
	"package-cleaner", # done
	"helpful-tools", # done
	"file-permissions", # done
	"kernel-harden", # done - has todos
	"prohibited-files", # done
	"service-management", # done, see todos
	"file-attributes", # done
	"upgrade-system", # done - see todos
]

REMOVE_IF_NOT_CRITICAL: Dict[str, str] = {
	"nginx": "nginx",
	"apache2": "apache2",
	"vsftpd": "vsftpd",
	"ssh": "openssh-server",
	"pure-ftpd": "pure-ftpd",
	"postfix": "postifx"
}

IGNORE_USERS: List[str] = [
	"root",
	"daemon",
	"bin",
	"sys",
	"sync",
	"games",
	"man",
	"lp",
	"mail",
	"news",
	"proxy",
	"www-data",
	"backup",
	"list",
	"irc",
	"gnats",
	"nobody",
	"systemd-network",
	"systemd-resolve",
	"uucp"
]

IGNORE_GROUPS: List[str] = [
	*IGNORE_USERS,
	"adm",
	"tty",
	"disk",
	"dialout",
	"fax",
	"cdrom",
	"floppy",
	"tape",
	"sudo",
	"operator",
	"plugdev",
	"users",

	"kmem",
	"voice",
	"audio",
	"dip",
	"src",
	"shadow",
	"utmp",
	"video",
	"sasl",
	"staff",
	"nogroup"
]

CONTINUE_PROMPT = "<enter to continue, CTRL-C at any time to exit> "

SSH_NONDEFAULT_PORT = 4097

OS_VERSION_NAME: str = re.search("VERSION_CODENAME=(\w*)", open("/etc/os-release", 'r').read()).group(1)

if OS_VERSION_NAME == "vanessa":
	OS_VERSION_NAME = "jammy"

def get_file_flags(filename: str) -> int:
	if os.path.isfile(filename):
		return struct.unpack(
			'I',
			fcntl.ioctl(
				open(filename, "rb"), 
				FS_IOC_GETFLAGS, 
				struct.pack('I', 0)
			)
		)[0]

	try:
		dir_fd = os.open(filename, os.O_RDONLY)
		
		return struct.unpack(
			'I',
			fcntl.ioctl(
				dir_fd,
				FS_IOC_GETFLAGS,
				struct.pack('I', 0)
			)
		)[0]
	finally:
		os.close(dir_fd)

def set_file_flags(filename: str, flags: int):
	if os.path.isfile(filename):
		fcntl.ioctl(
			open(filename, "wb"),
			FS_IOC_SETFLAGS,
			struct.pack('I', flags)
		)

		return
	
	try:
		dir_fd = os.open(filename, os.O_WRONLY)
		
		fcntl.ioctl(
			dir_fd,
			FS_IOC_SETFLAGS,
			struct.pack('I', flags)
		)
	finally:
		os.close(dir_fd)

def file_attributes():
	for root, dirs, files in os.walk('/', followlinks=False):
		# We can't lsattr these dirs, /usr is a special case that we don't want to search
		if root.startswith(("/snap", "/tmp", "/proc", "/sys", "/dev", "/mnt", "/run", "/boot")): continue
		
		for name in (item for collection in (dirs, files) for item in collection if not item.startswith('.')):
			filepath = os.path.join(root, name)

			if filepath in ("/init", "/dev", "/sys", "/proc", "/run"): continue

			if os.path.islink(filepath): continue

			try:
				flags = get_file_flags(filepath)

				if (flags != FS_EXTENT_FL) and (flags != (FS_EXTENT_FL | FS_INDEX_FL)):
					if flags & FS_IMMUTABLE_FL:
						warn(f"{filepath} has FS_IMMUTABLE set")

					with utils.io_lock:
						subprocess.call(["lsattr", "-d", filepath])
						print(f"note: {filepath}'s attrs above")

						set_to_extent = bool_input_nolock(f"WARNING: {filepath}'s attributes are not [FS_EXTENT] or [FS_EXTENT | FS_INDEX], set to [FS_EXTENT] ?")

						if set_to_extent:
							set_file_flags(filepath, FS_EXTENT_FL)
							print("flags set")

			except Exception:
				warn(f"could not ioctl {filepath} for querying attributes")

def usb_security(): # TODO: log
	# open("/etc/modprobe.d/deb-secure.conf", 'w').write("install usb-storage /bin/false\nblacklist usb-storage")
	pass

def gsettings_and_gdm_config(): # TODO: log
	apt.install("dconf-cli")

	sys("gsettings set org.gnome.desktop.screensaver lock-enabled true")
	sys("gsettings set org.gnome.desktop.screensaver lock-delay 0")
	sys("gsettings set org.gnome.desktop.session idle-delay 900")
	sys("gsettings set org.gnome.settings-daemon.plugins.media-keys logout []")
	sys("dconf update")

	try:
		gdm_config = open("/etc/gdm3/custom.conf", 'r').read()

		open("/etc/gdm3/custom.conf", 'w').write(
			set_config_variable(
				gdm_config,
				"AutomaticLoginEnable", "false", '='
			)
		)
	except FileNotFoundError: pass # we are not using gdm3

def lightdm_config():
		try:
			lightdm_conf = open("/etc/lightdm/lightdm.conf", 'r').read()
			lightdm_conf = set_config_variable(lightdm_conf, "allow-guest", "false", '=')
			lightdm_conf = set_config_variable(lightdm_conf, "greeter-hide-users", "true", '=')

			open("/etc/lightdm/lightdm.conf", 'w').write(lightdm_conf)
		except FileNotFoundError: pass # we are not using gdm3

def disable_ctrl_alt_del():
	sys("systemctl disable ctrl-alt-del.target")
	sys("systemctl mask ctrl-alt-del.target")
	sys("systemctl daemon-reload")

def service_management(): # TODO: start stopped critical services
	services = threaded_input("Enter a comma-separated list of critical services (no spaces) ").split(',')

	running_services = [removeprefix_compat(line, " [ + ]").strip() for line in subprocess.check_output(["service", "--status-all"]).decode().splitlines() if line.startswith(" [ + ]")]

	stopped: list[str] = []

	for servicename in REMOVE_IF_NOT_CRITICAL:
		if servicename in running_services and servicename not in services:
			if bool_input(f"Non-critical service {servicename} found, stop? "):
				sys(f"systemctl stop {servicename}")
				sys(f"systemctl disable {servicename}")
				stopped.append(servicename)

	for servicename, packagename in REMOVE_IF_NOT_CRITICAL.items():
		if servicename in stopped: # autoremove those that we stopped
			apt.remove(packagename)
			continue

def prohibited_files():
	prohibited_files = (
		glob.glob("/home/**/*.mp3", recursive=True) + 
		glob.glob("/home/**/*.mp4", recursive=True)
	)

	with utils.io_lock:
		print("found the following mp3 and mp4 files in /home (to remove, provide comma-sep list or 'all'): ")

		for i, mp3 in enumerate(prohibited_files):
			print(f"{i}: {mp3}")

		remove = input("choice: ")

	if not remove: return

	if remove == "all":
		rmrf(*prohibited_files)

	else:
		remove_idxs = [int(idx) for idx in remove.split(',')]

		for idx in remove_idxs:
			rmrf(prohibited_files[idx])


def vsftpd_config():
	sys("ufw allow ftp")
	sys("ufw reload")

	conf = open("/etc/vsftpd.conf", 'r').read()

	conf = set_config_variable(conf, "anonymous_enable", "NO", sep='=')
	conf = set_config_variable(conf, "ssl_enable", "YES", sep='=')

	open("/etc/vsftpd.conf", 'w').write(conf)


def nginx_config():
	default_secure_nginx_conf = """
user www-data;
worker_processes 4;
pid /run/nginx.pid;

events {
	worker_connections 1024;
}

http {
	sendfile on;
	tcp_nopush off;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;
	server_tokens off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
	ssl_prefer_server_ciphers on;

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	gzip off;

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
"""
	with open("/etc/nginx/nginx.conf", 'w') as f:
		f.write(default_secure_nginx_conf)

def apache2_config():
	conf = open("/etc/apache2/apache2.conf", 'r').read()

	conf = set_config_variable(conf, "ServerTokens", "Prod")
	conf = set_config_variable(conf, "ServerSignature", "Off")
	conf = set_config_variable(conf, "Header", "unset X-Powered-By")
	conf = set_config_variable(conf, "Header", "edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure")
	conf = set_config_variable(conf, "Header", 'set X-XSS-Protection "1; mode=block"')
	conf = set_config_variable(conf, "TraceEnable", "Off")

	open("/etc/apache2/apache2.conf", 'w').write(conf)



def apt_config():
	custom_override_conf = """
Acquire::http::AllowRedirect "false";
APT::Get::AllowUnauthenticated "false";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Install-zRecommends "false";
APT::Get::AutomaticRemove "true";
APT::Install-Suggests "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
Acquire::AllowInsecureRepositories "false";
APT::Sandbox::Seccomp "1";
"""

	open("/etc/apt/apt.conf.d/97deb-secure", 'w').write(custom_override_conf)

	try: conf = open("/etc/apt/apt.conf.d/50unattended-upgrades", 'r').read()
	except FileNotFoundError: conf = ""

	conf = set_config_variable(conf, "Unattended-Upgrade::Remove-Unused-Dependencies", '"true";')
	conf = set_config_variable(conf, "Unattended-Upgrade::Remove-Unused-Kernel-Packages", '"true";')
	conf = set_config_variable(conf, "Unattended-Upgrade::Automatic-Reboot", '"true";')
	conf = set_config_variable(conf, "Unattended-Upgrade::Automatic-Reboot-Time", '"03:00	";')


	open("/etc/apt/apt.conf.d/50unattended-upgrades", 'w').write(conf)

	sys("cp /etc/apt/sources.list /etc/apt/sources.list.old")

	apt_sources = f"""
deb http://archive.ubuntu.com/ubuntu/ {OS_VERSION_NAME} main restricted

# Updates for main and restricted packages
deb http://archive.ubuntu.com/ubuntu/ {OS_VERSION_NAME}-updates main restricted

# Universe repositories
deb http://archive.ubuntu.com/ubuntu/ {OS_VERSION_NAME} universe
deb http://archive.ubuntu.com/ubuntu/ {OS_VERSION_NAME}-updates universe

# Multiverse repositories
deb http://archive.ubuntu.com/ubuntu/ {OS_VERSION_NAME} multiverse
deb http://archive.ubuntu.com/ubuntu/ {OS_VERSION_NAME}-updates multiverse

# Security updates
deb http://security.ubuntu.com/ubuntu {OS_VERSION_NAME}-security main restricted
deb http://security.ubuntu.com/ubuntu {OS_VERSION_NAME}-security universe
deb http://security.ubuntu.com/ubuntu {OS_VERSION_NAME}-security multiverse

# Backports repository
deb http://archive.ubuntu.com/ubuntu/ {OS_VERSION_NAME}-backports main restricted universe multiverse
"""

	open("/etc/apt/sources.list", 'w').write(apt_sources)


def sshd_config(): # TODO: use regex to make sure necessary lines are uncommented, add more, including keys for users
	sys(f"ufw allow {SSH_NONDEFAULT_PORT}")
	sys("ufw reload")



	try:
		conf = open("/etc/ssh/sshd_config", 'r').read()

		conf = set_config_variable(conf, "Port", str(SSH_NONDEFAULT_PORT))
		conf = set_config_variable(conf, "LoginGraceTime", "20")
		conf = set_config_variable(conf, "PermitRootLogin", "no")
		conf = set_config_variable(conf, "PermitEmptyPasswords", "no")
		conf = set_config_variable(conf, "PermitUserEnvironment", "no")
		conf = set_config_variable(conf, "PermitTunnel", "no")
		conf = set_config_variable(conf, "PubkeyAuthentication", "yes")
		conf = set_config_variable(conf, "PasswordAuthentication", "no")
		conf = set_config_variable(conf, "X11Forwarding", "no")
		conf = set_config_variable(conf, "X11UseLocalhost", "yes")
		conf = set_config_variable(conf, "AllowTcpForwarding", "no")
		conf = set_config_variable(conf, "AllowAgentForwarding", "no")
		conf = set_config_variable(conf, "DebianBanner", "no")
		conf = set_config_variable(conf, "UsePAM", "yes")
		conf = set_config_variable(conf, "IgnoreRhosts", "yes")
		conf = set_config_variable(conf, "MaxAuthTries", '3')
		conf = set_config_variable(conf, "MaxSessions", '5')
		conf = set_config_variable(conf, "Ciphers", "aes256-ctr,aes256-gcm@openssh.com,aes192-ctr,aes128-ctr,aes128-gcm@openssh.com")
		conf = set_config_variable(conf, "ClientAliveInterval", "60")
		conf = set_config_variable(conf, "ClientAliveCountMax", '1')
		conf = set_config_variable(conf, "MACs", "hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com")
		conf = set_config_variable(conf, "KexAlgorithms", "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256")

		open("/etc/ssh/sshd_config", 'w').write(conf)

	except OSError as e: failure(e)
	
	sys("systemctl restart ssh")

def user_management(): # TODO: log all new
	sys("useradd -D -f 35") # disable inactive accounts after 35 days, TODO: log

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

	passwd = threaded_input("Please provide a secure password for all users: ")

	open("tmppass.txt", 'w').write(f"{passwd}\n{passwd}\n")


	admins = get_list_input("Enter an admin's name (blank for none/continue): ")
	users = get_list_input("Enter non-privileged user's name (blank for none/continue): ")

	all_authorized_users = [*admins, *users]

	with utils.io_lock:
		for user in pwd.getpwall():
			name = user.pw_name

			if name in IGNORE_USERS or (min_sys_uid <= user.pw_uid <= max_sys_uid):
				print(f"ignoring known system user {name} by default, continuing")
				continue

			if name == getpass.getuser(): # redundant case because the script must be run as root
				print(f"ignoring user {name} (self), continuing")

				if name in admins: admins.remove(name)
				continue

			if user.pw_uid == 0: # non-root uid 0 user, must delete
				remove = bool_input_nolock(f"URGENT: non-root uid 0 user {name} found, remove? ")

				if remove:
					sys(f"deluser {name}")

				continue

			print(f"attempting to update password expiry info for {user}...")
			sys(f"chage -M 90 -m 7 -W 14 {user}")

			if name in users:
				print(f"trying to remove {name} from admin group...")
				sys(f"deluser {name} adm")
				sys(f"deluser {name} sudo")

				users.remove(name)


			elif name in admins:
				print(f"trying to add {name} to admin & sudo groups...")
				sys(f"usermod -a -G adm {name}")
				sys(f"usermod -a -G sudo {name}")

				admins.remove(name)


			else:
				rem_user = bool_input_nolock(f"Unknown user {name} found, remove?")

				if rem_user:
					print(f"trying to delete {name}...")
					sys(f"deluser {name}")


					continue

			print(f"changing password for {name} to {passwd}...")

			_sys(
				f"passwd {name}",
				stdin=open("tmppass.txt")
			)

	for user in users:
		if bool_input(f"Non-privileged user {user} was not found, add?"):
			sys(f"useradd {user}")

			_sys(
				f"passwd {name}",
				stdin=open("tmppass.txt")
			)

	for adm in admins:
		if bool_input(f"Admin {adm} was not found, add?"):
			sys(f"useradd {adm}")
			sys(f"usermod -a -G adm {adm}")
			sys(f"usermod -a -G sudo {adm}")

			_sys(
				f"passwd {adm}",
				stdin=open("tmppass.txt")
			)

	rmrf("tmppass.txt")

	with utils.io_lock:
		groups_to_add = get_list_input_nolock("Enter a group you want to create (empty for none/continue): ")

		for groupname in groups_to_add:
			sys(f"groupadd {groupname}")

		for group in grp.getgrall():
			if group.gr_name in IGNORE_GROUPS or (min_sys_uid <= group.gr_gid <= max_sys_uid) or (group.gr_name in all_authorized_users):
				print(f"ignoring known system group {group.gr_name} by default, continuing")
				continue

			if bool_input_nolock(f"group {group.gr_name} has the following users: {', '.join(group.gr_mem)}, edit? (y/n) "):
				rem_members = get_list_input_nolock("Enter a member to remove (empty for none/continue): ")
				add_members = get_list_input_nolock("Enter a member to add (empty for none/continue): ")

				for member in rem_members:
					sys(f"deluser {member} {group.gr_name}")
				
				for member in add_members:
					sys(f"usermod -a -G {group.gr_name} {member}")
		
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
	bad_packages = (
		"samba-common", "icecast2",
		"zangband", "libpcap-dev", "ophcrack",
		"hydra", "deluge", "deluge-gtk", "wireshark", "nmap",
		"manaplus", "ettercap", "ettercap-graphical", "zenmap",
		"freeciv", "kismet-plugins",
		"libnet-akismet-perl",
		"ruby-akismet", "gameconqueror", "telnetd",     
		"rsh-server", "mines", "mahjongg", "sudoku", "aisleriot",
		"netcat-openbsd", "netcat-traditional", "ncat", "remmina",
		"john", "amule"
	)

	for package in bad_packages:
		apt.remove(package)

		with utils.io_lock: print(f"Attempted to remove package {package}")

	apt.autoremove()

def upgrade_system(): # TODO: maybe change /etc/apt/sources.list to see if necessary repos can be enabled
	apt.update()
	apt.upgrade()


def firewall(): # TODO: on this & other service configs RATE LIMIT - V-260517
	apt.install("ufw")

	sys(
"""
ufw default deny incoming
ufw default allow outgoing
ufw enable
""")
	



def file_permissions(): # TODO: V-260489, V-260490, V-260491
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
	sys("chmod 440 -R /etc/sudoers.d")
	sys("chmod 444 /etc/machine-id")

	sys("chmod 600 /etc/ssh/ssh_host_rsa_key")
	sys("chmod 600 /etc/ssh/ssh_host_ecdsa_key")
	sys("chmod 600 /etc/ssh/ssh_host_ed25519_key")

	sys("chown -R root:root /usr/sbin /usr/bin /usr/local/bin /usr/local/sbin /lib /lib64 /usr/lib")
	sys("chmod -R 755 /usr/sbin /usr/bin /usr/local/bin /usr/local/sbin /lib /lib64 /usr/lib")

	sys("chmod 4755 /usr/bin/sudo")
	sys("chmod 4755 /usr/bin/pkexec")

	sys("chown root:syslog /var/log")
	sys("chmod 750 /var/log")



	sys("chmod 740 /usr/bin/journalctl")



def password_policy(): # install tmpdir?, also see (V-260575, V-260574, V-260573), TODO: fix logging for all
	# TODO: tmpdir config (should it be session required or session optional?)
	# TODO: configure fail2ban

	apt.install("libpam-tmpdir")
	# 

	try:
		conf = open("/etc/login.defs", 'r').read()
		

		conf = '\n'.join(line for line in conf.splitlines() if not "PASS_" in line)

		conf = set_config_variable(conf, "PASS_MAX_DAYS", "90") # TODO: figure out why this just duplicates the variable instead of replacing it
		conf = set_config_variable(conf, "PASS_MIN_DAYS", '7')
		conf = set_config_variable(conf, "PASS_WARN_AGE", "14")
		conf = set_config_variable(conf, "ENCRYPT_METHOD", "SHA512")
		conf = set_config_variable(conf, "UMASK", "077")

		open("/etc/login.defs", 'w').write(conf)
	except OSError as e: failure(e)

	if OS_VERSION_NAME == "bionic":
		apt.install("libpam-cracklib", "libpam-modules") 

		try:
			passwd_conf = open("/etc/pam.d/common-password", 'r').read()

			try:
				pam_unix = re.search(r"pam_unix\.so.*$", passwd_conf, re.MULTILINE).group()
				cracklib = re.search(r"pam_cracklib\.so.*$", passwd_conf, re.MULTILINE).group()

				passwd_conf = passwd_conf.replace(pam_unix, f"pam_unix.so obscure use_authtok try_first_pass yescrypt")
				passwd_conf = passwd_conf.replace(cracklib, f"{cracklib} minlen=8 difok=3 dictcheck=1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1")

				passwd_conf = passwd_conf.replace("nullok", '')

				open("/etc/pam.d/common-password", 'w').write(passwd_conf)


			except (TypeError, AttributeError):
				failure("cracklib did not make its way into common-password")
		except OSError as e: failure(e)

		try:
			auth_conf = open("/etc/pam.d/common-auth", 'r').read()

			try:
				pam_tally2 = re.search(r"pam_tally2\.so.*$", auth_conf, re.MULTILINE).group()

				auth_conf = auth_conf.replace(pam_tally2, f"{pam_tally2} deny=5 unlock_time=1800")

			except (TypeError, AttributeError):
				auth_conf+="\n\nauth required pam_tally2.so onerr=fail deny=5 unlock_time=1800"

			open("/etc/pam.d/common-auth", 'w').write(auth_conf)
		except OSError as e: failure(e)		
	else:
		apt.install("libpam-pwquality", "libpam-modules")

		try:
			pwquality_conf = open("/etc/security/pwquality.conf", 'r').read()

			pwquality_conf = set_config_variable(pwquality_conf, "ucredit", "-1", sep=" = ")
			pwquality_conf = set_config_variable(pwquality_conf, "lcredit", "-1", sep=" = ")
			pwquality_conf = set_config_variable(pwquality_conf, "dcredit", "-1", sep=" = ")
			pwquality_conf = set_config_variable(pwquality_conf, "ocredit", "-1", sep=" = ")
			pwquality_conf = set_config_variable(pwquality_conf, "dictcheck", '1', sep=" = ")
			pwquality_conf = set_config_variable(pwquality_conf, "enforcing", '1', sep=" = ")
			pwquality_conf = set_config_variable(pwquality_conf, "difok", '8', sep=" = ")
			pwquality_conf = set_config_variable(pwquality_conf, "minlen", "15", sep=" = ")

			open("/etc/security/pwquality.conf", 'w').write(pwquality_conf)


			faillock_conf = open("/etc/security/faillock.conf", 'r').read()

			faillock_conf = set_config_variable(faillock_conf, "audit", '', sep='')
			faillock_conf = set_config_variable(faillock_conf, "silent", '', sep='')
			faillock_conf = set_config_variable(faillock_conf, "deny", '3', sep=" = ")
			faillock_conf = set_config_variable(faillock_conf, "fail_interval", "900", sep=" = ")
			faillock_conf = set_config_variable(faillock_conf, "unlock_time", '0', sep=" = ")

			open("/etc/security/faillock.conf", 'w').write(faillock_conf)


			auth_conf = open("/etc/pam.d/common-auth", 'r').read()

			for line in re.finditer(r"^.*pam_fail(lock|delay)\.so.*$", auth_conf, re.MULTILINE): # clear all faillock and faildelay lines
				auth_conf = auth_conf.replace(line.string, '')

			try:
				pam_unix = re.search(r"^.*pam_unix\.so.*$", auth_conf, re.MULTILINE).group()

				auth_conf = auth_conf.replace(pam_unix, f"auth	required	pam_faildelay.so delay=5000\nauth    required    pam_faillock.so preauth silent audit deny=5 unlock_time=1800\n\n{pam_unix}")

				pam_deny = re.search(r"^.*pam_deny\.so.*$", auth_conf, re.MULTILINE).group()

				auth_conf = auth_conf.replace(pam_deny, f"auth    [default=die] pam_faillock.so authfail audit deny=5 unlock_time=1800\nauth    sufficient pam_faillock.so authsucc audit deny=5 unlock_time=1800\n\n{pam_deny}")

				auth_conf = auth_conf.replace("nullok", '')

				open("/etc/pam.d/common-auth", 'w').write(auth_conf)
			except AttributeError:
				failure("did not apply auth changes") # fix

			acc_conf = open("/etc/pam.d/common-account", 'r').read()

			for line in re.finditer(r"^.*pam_faillock\.so.*$", acc_conf, re.MULTILINE): # clear all faillock lines
				acc_conf = acc_conf.replace(line.group(), '')

			auth_conf+="\n\naccount required pam_faillock.so"

			open("/etc/pam.d/common-account", 'w').write(acc_conf)


			login_conf = open("/etc/pam.d/login", 'r').read()

			try:
				pam_lastlog = re.search(r"^.*pam_lastlog\.so.*$", login_conf, re.MULTILINE).group()

				open("/etc/pam.d/login", 'w').write(login_conf)
			except AttributeError:
				failure("pam_lastlog line doesn't exist in login")


			passwd_conf = open("/etc/pam.d/common-password", 'r').read()
		
			try:				
				pam_unix = re.search(r"pam_unix\.so.*$", passwd_conf, re.MULTILINE).group()
				passwd_conf = passwd_conf.replace(pam_unix, f"pam_unix.so obscure use_authtok try_first_pass yescrypt")

				try:
					pam_pwquality = re.search(r"pam_pwquality\.so.*$", passwd_conf, re.MULTILINE).group()
					passwd_conf = passwd_conf.replace(pam_pwquality, "pam_pwquality.so retry=3 minlen=15 difok=8 ucredit=-1 dcredit=-1 ocredit=-1 lcredit=-1 dictcheck=1")
				except AttributeError:
					passwd_conf = "password requisite pam_pwquality.so retry=3 minlen=15 difok=8 ucredit=-1 dcredit=-1 ocredit=-1 lcredit=-1 dictcheck=1\n\n"+passwd_conf

				passwd_conf = passwd_conf.replace("nullok", '')

				open("/etc/pam.d/common-password", 'w').write(passwd_conf)
			except AttributeError:
				failure("pam_unix line doesn't exist in common-password")

		except OSError as e: failure(e)

	# FOR ALL VERSIONS

	sys("passwd -dl root")


def kernel_harden(): # removed sysctl -w kernel.modules_disabled=1 because it disallows nft to run
	custom_conf = """
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
net.ipv4.tcp_rfc1337=1
net.ipv4.ip_forward=0
"""

	open("/etc/sysctl.d/99-sysctl.conf", "a").write(custom_conf)

	sys("sysctl --system")


	sys("systemctl disable kdump") # TODO: check if works on fresh VM
	sys("systemctl mask kdump")
	sys("systemctl daemon-reload")


parser = argparse.ArgumentParser(description="Secure Debian-Based Systems", prog="secure")

parser.add_argument("-t", "--threads", nargs=1, default=1, type=int, help="run the script with n threads")

flaggroup = parser.add_mutually_exclusive_group(required=True)
flaggroup.add_argument("-i", "--include", nargs='*', default=[], help="use only the specified list of modules")
flaggroup.add_argument("-e", "--exclude", nargs='*', default=[], help="run with the default set of modules, excluding the ones specified in the list")
flaggroup.add_argument("-l", "--list", action="store_true")

args = parser.parse_args()

if args.include:
	modules: list[str] = args.include

	for module in modules:
		if module not in DEFAULT_MODULES:
			print(f"error: module '{module}' not available")
			exit(1)
elif args.exclude:
	modules = [item for item in DEFAULT_MODULES if item not in args.exclude]

	for module in args.exclude:
		if module not in DEFAULT_MODULES:
			print(f"warning: module '{module}' doesn't exist, skipping exclude for '{module}'")
else:
	for module in DEFAULT_MODULES:
		print(module)

	exit(0)

MAX_THREADS: int = args.threads

print(f"detected OS: Ubuntu {OS_VERSION_NAME}")

input(f"\n\ncontinuing with the following modules on {MAX_THREADS} threads: {' '.join(modules)} {CONTINUE_PROMPT}")

module_lookup = {
	"password-policy": password_policy,
	"package-cleaner": package_cleaner,
	"helpful-tools": helpful_tools,
	"upgrade-system": upgrade_system,
	"kernel-harden": kernel_harden,
	"file-permissions": file_permissions,
	"firewall": firewall,
	"sshd": sshd_config,
	"vsftpd": vsftpd_config,
	"nginx": nginx_config,
	"apache2": apache2_config,
	"user-management": user_management,
	"apt-config": apt_config,
	"prohibited-files": prohibited_files,
	"service-management": service_management,
	"ctrl-alt-del": disable_ctrl_alt_del,
	"gsettings-and-gdm-config": gsettings_and_gdm_config,
	"lightdm": lightdm_config,
	"file-attributes": file_attributes
}

def run_module(name: str) -> None:
	utils.thread_local.current_module = name

	with utils.io_lock: print(f"placed {name} on a new thread")

	module_lookup[name]()

	with utils.io_lock: print(f"module {name} complete, thread will be freed soon")

	del waiting_threads[name] 

def sigint_handler(_=None, __=None):
	print("ATTEMPTING TO ACQUIRE I/O LOCK")

	with utils.io_lock:
		print("All standard I/O operations on threads paused")

		while 1:
			print("What would you like to do?")
			option = input("e (exit), s (status), anything else for continue ").lower()

			if option == 'e':
				for mod, thread in waiting_threads.items():
					print(f"Waiting for {mod} to complete")
					thread.join()

				exit(0)

			if option == 's':
				for i, (name, _) in enumerate(waiting_threads.items()):
					print(f"Thread {i}: {name}")

				if utils.running_apt:
					print(f"APT running in module {utils.running_apt}")

				continue

			return

signal.signal(signal.SIGINT, sigint_handler)

waiting_threads: Dict[str, threading.Thread] = {}

for module in modules:
	while len(waiting_threads) == MAX_THREADS: pass

	next_task = threading.Thread(target=run_module, args=(module,), daemon=True)
	next_task.start()

	waiting_threads[module] = next_task

while len(waiting_threads) > 0: pass

# TODO: have the user input various services that are required
# TODO: see old script file
# TODO: log errors & redirect command output to log file
# TODO: ignore more system groups AND user-groups