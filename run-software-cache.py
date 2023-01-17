from utils import sys, apt

input("Continue to software manager?")
sys(f"software-properties-gtk --open-tab=2")

input("Continue to firefox?")
sys(f"firefox --preferences")

input("Continue once software cache has been reloaded")
apt.update()
apt.upgrade()

input("Exit? - RUN `SUDO REBOOT` IMMEDIATELY")
print("ALSO REMOVE AUTOLOGIN")
print("RUN LYNIS AGAIN AND READ THRU THE OUTPUT -> THERE ARE SYSCTL CONFS TOO")