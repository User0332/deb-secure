import pwd
from re import compile, MULTILINE as RE_MULTI
from utils import (
	apt, sys, _sys,
	rmrf, failure,
	get_usertype_input,
	generate_passwd
)

# verify sudo
if _sys("sudo echo passed") != 0:
	print("Please run this with sudo or in a su shell!")
	exit(1)

print("\n\n\n=> Basic package installs, updates upgrades...")

apt.update()
apt.upgrade()

# Install lynis
sys(
"""
wget -O - https://packages.cisofy.com/keys/cisofy-software-public.key | sudo apt-key add -
echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" | sudo tee /etc/apt/sources.list.d/cisofy-lynis.list
"""
)

apt.install(
	"ufw", 
	"net-tools",
	"chkrootkit",
	"clamav",
	"rkhunter",
	"Lynis",
	"libpam-cracklib"
)

apt.remove(
	"samba-common", "icecast2",
	"zangband", "npcap", "ophcrack",
	"hydra", "deluge", "wireshark",
	"utorrent", "nmap", "avernum",
	"manaplus", "ettercap", "zenmap",
	"freeciv", "kismet"
)

apt.clean()
apt.autoclean()
apt.autoremove()

sys(
"""
ufw enable
ufw reject incoming
ufw deny ftp
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

freshclam
clamscan -r -i /

lynis update info
lynis audit system
"""
)

input("Continue?")

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

print("\n\n\n=> Searching for backdoors... { try `whereis` maybe? }")
sys(
"""
netstat -ano -p tcp | grep "python|perl"
lsof | grep "python|perl"
"""
)

input("Continue?")

print("\n\n\n=> Configuring sshd_config...")
try:
	conf = open("/etc/ssh/sshd_config", 'r').read()

	conf.replace(
		"PermitRootLogin yes", "PermitRootLogin no"
	)

	conf.replace(
		"PermitEmptyPasswords yes", "PermitEmptyPasswords no"
	)

	open("/etc/ssh/sshd_config", 'w').write(conf)
except OSError as e: failure(e)

input("Continue?")

print("\n\n\n=> Configuring login.defs...")
try:
	conf = open("/etc/login.defs", 'r').read()

	re = compile(conf)

	max_days = re.match("^PASS_MAX_DAYS .* $", RE_MULTI).group()
	min_days = re.match("^PASS_MIN_DAYS .* $", RE_MULTI).group()
	warn_days = re.match("^PASS_WARN_AGE .* $", RE_MULTI).group()
	encrypt_method = re.match("^ENCRYPT_METHOD .* $", RE_MULTI)

	conf.replace(max_days, "PASS_MAX_DAYS 90")
	conf.replace(min_days, "PASS_MIN_DAYS 10")
	conf.replace(warn_days, "PASS_WARN_AGE 7")
	conf.replace(encrypt_method, "ENCRYPT_METHOD SHA512")

	open("/etc/login.defs", 'w').write(conf)
except OSError as e: failure(e)

input("Continue?")

print("\n\n\n=> Configuring common-password...")
try:
	conf = open("/etc/pam.d/common-password", 'r').read()

	re = compile(conf)

	pam_unix = re.match("^pam_unix.so .* $", RE_MULTI).group()
	cracklib = re.match("^pam_cracklib.so .* $", RE_MULTI).group()

	conf.replace(pam_unix, f"{pam_unix} remember=5 minlen=8")
	conf.replace(cracklib, f"{cracklib} ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1")


	open("/etc/pam.d/common-password", 'w').write(conf)
except OSError as e: failure(e)

print("\n\n\n=> Configuring common-auth...")
try:
	conf = open("/etc/pam.d/common-auth", 'r').read()

	conf+="\n\nauth required pam_tally2.so deny=5 onerr=fail unlock_time=1800"

	open("/etc/pam.d/common-auth", 'w').write(conf)
except OSError as e: failure(e)

input("Continue?")

print("\n\n\n=> Configuring sysctl...")
sys(
"""
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv4.ip_forwarding=0

sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
"""
)

input("Continue?")

print("\n\n\n=> Configuring cron.allow and at.allow to only allow root...")
rmrf("cron.deny", "at.deny")
sys(
"""
echo root > cron.allow
echo root > at.allow

chown root cron.allow at.allow
chmod 600 cron.allow at.allow
"""
)


input("Continue?")

print("\n\n\n=> Services: { may want to remove apache2, nginx, samba, etc. }")
sys("service --status-all")

input("Continue?")

print("\n\n\n=> Looping thru users")

for user in pwd.getpwall():
	user_type = get_usertype_input(user.pw_name)

	if user_type == "none":
		print(f"trying to delete {user}...")
		sys(f"deluser {user}")

	if user_type == "std":
		print(f"trying to remove {user} from admin group...")
		sys(f"deluser {user} admin")

		new_passwd, passwd_file = generate_passwd(user)

		print(f"trying to secure this user's password... ({new_passwd=})")
		with open(passwd_file, 'r') as f:
			_sys(
				f"passwd {user}",
				stdin=f
			)

	if user_type == "adm":
		print(f"trying to add {user} to admin group...")
		sys(f"usermod -a -G admin {user}")

input("Continue?")

sys("update-manager")

input("Exit?")


# TODO: ETC File configs thru commands like `sysctl` => 
#   - USE THE ENTIRETY OF THE GOLD CHECKLIST, EVEN WHATEVER IS ON THE BOTTOM
# TODO: Read thru the other guy's script => check out the iptables nonsense

# NOTE: Purple update config from the command line was scrapped,
# it just opens up the update manager now for the user to configure manually