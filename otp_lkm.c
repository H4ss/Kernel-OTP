#include <linux/module.h>
#include <linux/init.h>
#include "base_otp.h"
#include "time_otp.h"

//printk(KERN_INFO "OTP Module: Initializing.\n");

static int __init otp_module_init(void) {
    printk(KERN_INFO "OTP Module: Initializing.\n");
    
    // Initialize the list-based OTP mechanism
    if (list_otp_init() != 0) {
        printk(KERN_ALERT "List-based OTP initialization failed.\n");
        // Handle partial initialization failure if necessary
        return -1;
    }
    
    // Initialize the time-based OTP mechanism
    if (time_otp_init() != 0) {
        printk(KERN_ALERT "Time-based OTP initialization failed.\n");
        // Cleanup already initialized parts if necessary
        return -1;
    }
    
    printk(KERN_INFO "OTP Module: Successfully initialized both mechanisms.\n");
    return 0; // Indicate successful initialization
}

static void __exit otp_module_exit(void) {
    // Clean up the list-based OTP mechanism
    list_otp_exit();  
    
    // Clean up the time-based OTP mechanism
    time_otp_exit();  
    
    printk(KERN_INFO "OTP Module: Exiting.\n");
}

module_init(otp_module_init);
module_exit(otp_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hassan ZABATT");
MODULE_AUTHOR("Florent ROSSIGNOL");
MODULE_AUTHOR("Pol-Antoine LOISEAU");
MODULE_DESCRIPTION("Time OTP and simple OTP with dynamic listing.");
MODULE_VERSION("0.4");