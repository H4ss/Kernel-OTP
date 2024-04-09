#include "base_otp.h"
#include "time_otp.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hassan ZABATT");
MODULE_AUTHOR("Florent ROSSIGNOL");
MODULE_AUTHOR("Pol-Antoine LOISEAU");
MODULE_DESCRIPTION("Simple OTP with dynamic listing.");
MODULE_VERSION("0.4");

static int __init otp_module_init(void) {
    printk(KERN_INFO "OTP Module: Initializing.\n");
    list_otp_init();  // Initialize the list-based OTP mechanism
    time_otp_init();  // Initialize the time-based OTP mechanism
    return 0;  // Indicate successful initialization
}

static void __exit otp_module_exit(void) {
    list_otp_exit();  // Clean up the list-based OTP mechanism
    time_otp_exit();  // Clean up the time-based OTP mechanism
    printk(KERN_INFO "OTP Module: Exiting.\n");
}

module_init(otp_module_init);
module_exit(otp_module_exit);