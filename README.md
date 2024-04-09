# Kernel-OTP


## env setup

1. Virtual Box with ubuntu 22.04

2. 4 core allocated, 4gb of RAM and 30gb of storage
   
3. IMPORTANT: have the 5.15 kernel ! the kernl API is not exactly the same between the 5.15 and the latest one 


## launch step:

1. make (from the base directory)

2. sudo insmod base_otp.ko

3. dmesg | (the status msg appears at the end)

4. python3 otp.py
   - add a password to the list
   - remove a password from the list
   - fetch a password
   - validate a fetched password

6. sudo rmmod base_otp

TODO:
- check that we cannot remove a password that is non existant
- adding the world readable permissions to the created devices to use to python tool in non-root

### USEFUL COMMANDS

sudo -i  
cd /media/sf_kernel # where my shared folder is  
code . --no-sandbox --user-data-dir "." # vscode with the sudo mode on  

### KERNEL DOWNGRADE

apt install linux-image-5.15.0-78-generic (the version that i choose)    
grub-update  
reboot  

- (on vbox) hold shift at the startup menu -> grub -> advanced options -> select the right KERNEL -> boot  

uname -r # if the kernel effectively changed then pursue  
apt install linux-headers-$(uname -r)  
apt install build-essential
