#ifndef TIME_OTP_H
#define TIME_OTP_H

#include <linux/init.h> // For __init and __exit macros

int __init time_otp_init(void);
void __exit time_otp_exit(void);

#endif // TIME_OTP_H