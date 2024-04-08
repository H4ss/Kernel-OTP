#include <linux/init.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "otp_list"
#define CLASS_NAME  "otp"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hassan ZABATT");
MODULE_DESCRIPTION("Un simple module Linux pour OTP basé sur une liste.");
MODULE_VERSION("0.1");

static int    majorNumber;
static char   otpList[10][256] = {"OTP1", "OTP2", "OTP3", "OTP4", "OTP5", "OTP6", "OTP7", "OTP8", "OTP9", "OTP10"};
static int    currentOTP = 0;
static struct class*  otpClass  = NULL;
static struct device* otpDevice = NULL;

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);

static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .release = dev_release,
};

static int __init otp_init(void) {
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber<0) {
        printk(KERN_ALERT "OTP failed to register a major number\n");
        return majorNumber;
    }
    otpClass = class_create(THIS_MODULE, CLASS_NAME);
    otpDevice = device_create(otpClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    printk(KERN_INFO "OTP: device class created correctly\n");
    return 0;
}

static void __exit otp_exit(void) {
    device_destroy(otpClass, MKDEV(majorNumber, 0));
    class_unregister(otpClass);
    class_destroy(otpClass);
    unregister_chrdev(majorNumber, DEVICE_NAME);
    printk(KERN_INFO "OTP: Goodbye!\n");
}

static int dev_open(struct inode *inodep, struct file *filep) {
   printk(KERN_INFO "OTP: Device has been opened\n");
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
   static int finished = 0;
   int error_count = 0;
   if (finished) {
      finished = 0; // Reset the finished flag
      return 0; // Signal EOF
   }
   if (currentOTP >= 10) {
      printk(KERN_INFO "OTP: No more OTPs available\n");
      return 0; // No more OTPs
   }
   error_count = copy_to_user(buffer, otpList[currentOTP], strlen(otpList[currentOTP]));
   if (error_count==0) {
      printk(KERN_INFO "OTP: Sent OTP %d to the user\n", currentOTP);
      currentOTP++; // Move to the next OTP
      finished = 1; // Set the finished flag
      return strlen(otpList[currentOTP - 1]); // Return the size of OTP sent
   } else {
      printk(KERN_ALERT "OTP: Failed to send OTP to the user\n");
      return -EFAULT;
   }
}

static int dev_release(struct inode *inodep, struct file *filep) {
   printk(KERN_INFO "OTP: Device successfully closed\n");
   return 0;
}

module_init(otp_init);
module_exit(otp_exit);
