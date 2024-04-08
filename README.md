# Kernel-OTP


## env setup

1. Virtual Box with ubuntu 22.04

2. 4 core allocated, 4gb of RAM and 30gb of storage


## launch step:

1. make (from the base directory)

2. sudo insmod base_otp.ko

3. dmesg (the hello msg appears at the end)

4. sudo rmmod base_otp


### USEFUL COMMANDS

su # gain some time
cd /media/sf_kernel # where my shared folder is
code . --no-sandbox --user-data-dir "." # vscode with the sudo mode on

### KERNEL DOWNGRADE

apt install linux-image-5.15.0-78-generic
grub-update
reboot

- (on vbox) hold shift at the startup menu -> grub -> advanced options -> select the right KERNEL -> boot

uname -r # if the kernel effectively changed then pursue
apt install linux-headers-$(uname -r)
apt install build-essential