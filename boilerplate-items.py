import pwd
import re
from utils import (
	apt, sys, _sys,
	rmrf, failure,
	get_usertype_input,
	generate_passwd
)

print("\n\n\n=> Basic package installs, remove bad packages")

# Install lynis
sys(
"""
bash -c wget -O - https://packages.cisofy.com/keys/cisofy-software-public.key | sudo apt-key add -
bash -c echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" | sudo tee /etc/apt/sources.list.d/cisofy-lynis.list
"""
)

apt.install(
	"ufw", 
	"net-tools",
	"chkrootkit",
	"rkhunter",
	"lynis",
	"libpam-cracklib",
	"stacer"
)


apt.remove(
	"samba-common", "icecast2",
	"zangband", "libpcap-dev", "ophcrack",
	"hydra", "deluge", "wireshark",
	"utorrent", "nmap", "avernum",
	"manaplus", "ettercap", "ettercap-graphical", "zenmap",
	"freeciv", "kismet-plugins",
	"libnet-akismet-perl",
	"ruby-akismet"
)

apt.clean()
apt.autoclean()
apt.autoremove()

sys(
"""
ufw default reject incoming
ufw deny ftp
ufw enable
"""
)

input("Continue? Note => apache2 and nginx were not removed if present.")

print("\n\n\n=> Running Antivirus Software... { chkrootkit, lynis, rkhunter, clamav }")

sys(
"""
chkrootkit -q

rkhunter --update
rkhunter --propupd
rkhunter --check --rwo

lynis update info
lynis audit system
"""
)

input("Continue?")

# TODO: ALL FIND CMDS ARE BROKEN
print("\n\n\n=> Music, Image & Video Files:")
sys(
"""
find / -name "*.mp3"
find / -name "*.mp4"
find / -name "*.ogg"
find / -name "*.wav"
find / -name "*.png"
find / -name "*.jpg"
find / -name "*.avi"
find / -name "*.mpg"
find / -name "*.mpeg"
find / -name "*.flac"
find / -name "*.m4a"
find / -name "*.flv"
find / -name "*.gif"
find / -name "*.png"
find / -name "*.jpeg"
"""
)

input("Continue?")

print("\n\n\n=> Files that may contain sensitive info:")
sys(
"""
find / -name "*secret*"
find / -name "*SECRET*"
find /home -name "*.txt"
"""
)

input("Continue?")

print("\n\n\n=> Searching for backdoors (netstat)... { try `whereis` maybe? }")
sys(
"""
bash -c netstat -ano -p tcp | grep -E "python|perl|\\.py|\\.pl"
"""
)

print("\n\n\n=> Searching for backdoors (lsof)... { try `whereis` maybe? }")
sys(
"""
bash -c lsof | grep -E "python|perl|\\.py|\\.pl"
"""
)

input("Continue?")

print("\n\n\n=> Configuring sshd_config...")
try:
	conf = open("/etc/ssh/sshd_config", 'r').read()

	conf = conf.replace(
		"PermitRootLogin yes", "PermitRootLogin no"
	)

	conf = conf.replace(
		"PermitEmptyPasswords yes", "PermitEmptyPasswords no"
	)

	conf = conf.replace(
		"X11Forwarding yes", "X11Forwarding no"
	)

	open("/etc/ssh/sshd_config", 'w').write(conf)
except OSError as e: failure(e)

input("Continue?")

print("\n\n\n=> Configuring login.defs...")
try:
	conf = open("/etc/login.defs", 'r').read()

	max_days = re.search("^PASS_MAX_DAYS.*$", conf, re.MULTILINE).group()
	min_days = re.search("^PASS_MIN_DAYS.*$", conf, re.MULTILINE).group()
	warn_days = re.search("^PASS_WARN_AGE.*$", conf, re.MULTILINE).group()
	encrypt_method = re.search("^ENCRYPT_METHOD.*$", conf, re.MULTILINE).group()

	conf = conf.replace(max_days, "PASS_MAX_DAYS\t90")
	conf = conf.replace(min_days, "PASS_MIN_DAYS\t10")
	conf = conf.replace(warn_days, "PASS_WARN_AGE\t7")
	conf = conf.replace(encrypt_method, "ENCRYPT_METHOD SHA512")

	open("/etc/login.defs", 'w').write(conf)
except OSError as e: failure(e)

input("Continue?") 

print("\n\n\n=> Configuring common-password... SET MANUALLY IF FAIL")
try:
	conf = open("/etc/pam.d/common-password", 'r').read()

	try:
		pam_unix = re.search("pam_unix\.so.*$", conf, re.MULTILINE).group()
		cracklib = re.search("pam_cracklib\.so.*$", conf, re.MULTILINE).group()

		conf = conf.replace(pam_unix, f"{pam_unix} remember=5 minlen=8")
		conf = conf.replace(cracklib, f"{cracklib} ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1")
	except TypeError:
		conf+=f"\n\n{cracklib} ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=4"

	open("/etc/pam.d/common-password", 'w').write(conf)
except (OSError, AttributeError) as e: failure(e)

print("\n\n\n=> Configuring common-auth...")
try:
	open("/etc/pam.d/common-auth", 'a') \
		.write("\n\nauth required pam_faillock.so deny=5 onerr=fail unlock_time=1800")
except OSError as e: failure(e)

input("Continue?")

print("\n\n\n=> Configuring sysctl...") ## do all vars qu'lyins recommends
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
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv4.ip_forwarding=0
"""
)

input("Continue?")

print("\n\n\n=> Configuring cron.allow and at.allow to only allow root...")
input("NEED TO SET THIS MANUALLY IF IT DOESN'T WORK -> enter to continue")
rmrf("/etc/cron.d/cron.deny", "/etc/cron.d/at.deny")
sys(
"""
bash -c echo root > /etc/cron.d/cron.allow
bash -c echo root > /etc/cron.d/at.allow

chown root /etc/cron.d/cron.allow /etc/cron.d/at.allow
chmod 600 /etc/cron.d/cron.allow /etc/cron.d/at.allow
"""
)


input("Continue?")

print("\n\n\n=> Services: { may want to remove apache2, nginx, samba, etc. }")
sys("service --status-all")

input("Continue?")

print("\n\n\nsetting /etc/ file perms [-R 700]")
sys("chmod -R 700 /etc")

input("Continue?")

print("\n\n\n=> Looping thru users")

for user in pwd.getpwall():
	name = user.pw_name

	user_type = get_usertype_input(name)

	if user_type == "none":
		print(f"trying to delete {name}...")
		sys(f"deluser {name}")

	if user_type == "std":
		print(f"trying to remove {name} from admin group...")
		sys(f"deluser {name} adm") # Cyb3rPatri0t!
		sys(f"deluser {name} sudo")

		new_passwd, passwd_file = generate_passwd(name)

		print(f"trying to secure {name}'s password... ({new_passwd=})")
		with open(passwd_file, 'r') as f:
			_sys(
				f"passwd {name}",
				stdin=f
			)

	if user_type == "adm":
		print(f"trying to add {name} to admin group...")
		sys(f"usermod -a -G adm {name}")

input("Continue? (next update, upgrade)")

apt.update()
apt.upgrade()

input("Exit? RUN run-software-cache.py after exiting WITHOUT SUDO")

sys("stacer")


# TODO: ETC File configs thru commands like `sysctl` => 
#   - USE THE ENTIRETY OF THE GOLD CHECKLIST, EVEN WHATEVER IS ON THE BOTTOM

# TODO: Remove autologin

# TODO: Read thru the other guy's script => check out the iptables nonsense

# NOTE: Purple update config from the command line was scrapped,
# it just opens up the update manager now for the user to configure manually

# NOTE: The script does not: 
# - Config Firefox (opens firefox window)
# - Perform System Update Config (opens the window)
# - Change bad admin passwds
# - Config all needed /etc/ files
# - Set cron.allow (sometimes failes)

# NOTE: CLAMAV REMOVED FOR UNKNOWN BUG