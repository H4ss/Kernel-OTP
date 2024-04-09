#ifndef BASE_OTP_H
#define BASE_OTP_H

#include <linux/init.h> // For __init and __exit macros

// Function declarations
int __init list_otp_init(void);
void __exit list_otp_exit(void);

#endif // BASE_OTP_H