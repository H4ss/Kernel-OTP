#include <linux/init.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h> 

#define DEVICE_NAME "otp_list"
#define CLASS_NAME  "otp"
#define MAX_OTP_LENGTH 256

static int    majorNumber;
static struct class*  otpClass  = NULL;
static struct device* otpDevice = NULL;

struct otp_node {
   char otp[MAX_OTP_LENGTH];
   struct list_head list; // Kernel's list structure to link nodes
};

static LIST_HEAD(otp_list);

// Device file operations prototypes
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops = {
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
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

static void add_otp(const char* new_otp) {
   struct otp_node *node;

   // Allocate memory for a new OTP node
   node = kmalloc(sizeof(*node), GFP_KERNEL);
   if (!node) {
      printk(KERN_ALERT "OTP: Failed to allocate memory for OTP node.\n");
      return;
   }
   strncpy(node->otp, new_otp, MAX_OTP_LENGTH - 1);
   node->otp[MAX_OTP_LENGTH - 1] = '\0';

   // Initialize and add the new node to the list
   INIT_LIST_HEAD(&node->list);
   list_add_tail(&node->list, &otp_list);
   printk(KERN_INFO "OTP: Added new OTP.\n");
}

static void remove_otp(const char* otp_to_remove) {
   struct otp_node *node, *tmp;
   bool found = false;

   // Iterate over the list of OTPs
   list_for_each_entry_safe(node, tmp, &otp_list, list) {
      if (strcmp(node->otp, otp_to_remove) == 0) {
         // OTP match found, remove from the list and free the memory
         list_del(&node->list);
         kfree(node);
         found = true;
         printk(KERN_INFO "OTP: Removed OTP %s.\n", otp_to_remove);
         break;
      }
   }

   if (!found) {
      printk(KERN_INFO "OTP: OTP %s not found.\n", otp_to_remove);
   }
}

static int dev_open(struct inode *inodep, struct file *filep) {
   printk(KERN_INFO "OTP: Device has been opened\n");
   return 0;
}

static int dev_release(struct inode *inodep, struct file *filep) {
   printk(KERN_INFO "OTP: Device successfully closed\n");
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
   struct otp_node *first_node;
   ssize_t bytes_not_copied;

   // Check if we've already read an OTP during this open session
   if (*offset > 0) {
      return 0;
   }

   if (list_empty(&otp_list)) {
      printk(KERN_INFO "OTP: No OTPs available.\n");
      return 0;
   }

   first_node = list_first_entry(&otp_list, struct otp_node, list);
   if (len < strlen(first_node->otp) + 2) {
      printk(KERN_WARNING "OTP: Buffer too small for OTP.\n");
      return -EFAULT;
   }
   bytes_not_copied = copy_to_user(buffer, first_node->otp, strlen(first_node->otp));
   if (bytes_not_copied == 0) {
      put_user('\n', buffer + strlen(first_node->otp));
      printk(KERN_INFO "OTP: Provided OTP to user.\n");
      list_del(&first_node->list);
      kfree(first_node);
      *offset += strlen(first_node->otp) + 1;
      return strlen(first_node->otp) + 1;
   } else {
      printk(KERN_WARNING "OTP: Failed to copy OTP to user space.\n");
      return -EFAULT;
   }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
   char *command;


   command = kmalloc(len+1, GFP_KERNEL);
   if (!command) {
      printk(KERN_ALERT "OTP: Failed to allocate memory for command.\n");
      return -ENOMEM;
   }

   if (copy_from_user(command, buffer, len)) {
      printk(KERN_ALERT "OTP: Failed to copy command from user space.\n");
      kfree(command);
      return -EFAULT;
   }

   command[len] = '\0';
   if (strncmp(command, "add:", 4) == 0) {
      add_otp(command + 4);
   } else if (strncmp(command, "remove:", 7) == 0) {
      remove_otp(command + 7);
   } else {
      printk(KERN_INFO "OTP: Unknown command.\n");
   }

   kfree(command);
   return len;
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hassan ZABATT");
MODULE_AUTHOR("Florent ROSSIGNOL");
MODULE_AUTHOR("Pol-Antoine LOISEAU");
MODULE_DESCRIPTION("Simple OTP with dynamic listing.");
MODULE_VERSION("0.4");

module_init(otp_init);
module_exit(otp_exit);