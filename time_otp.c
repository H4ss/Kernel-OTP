#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <crypto/sha1.h>

#include "time_otp.h"

#define DEVICE_NAME "otp_time"
#define CLASS_NAME "totp"
#define TOTP_MAX_SECRET_KEY_SIZE 32
#define TOTP_DIGITS 6

static int    majorNumber;
static struct class*  otpClass  = NULL;
static struct device* otpTimeDevice = NULL;
static int dev_open(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static int dev_release(struct inode *, struct file *);

static char totp_secret_key[TOTP_MAX_SECRET_KEY_SIZE] = "Bonjour";
static ssize_t totp_secret_key_size = 7;
static unsigned int totp_time_step = 30;

static DEFINE_MUTEX(totp_key_mutex);

// File operations structure
static struct file_operations fops = {
    .open = dev_open,
    .read = dev_read,
    .write = dev_write,
    .release = dev_release,
};

int __init time_otp_init(void) {
    printk(KERN_INFO "Time-based OTP: Initializing\n");

    // Register the device - dynamically allocate a major number
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops); // fops to be defined
    if (majorNumber < 0) {
        printk(KERN_ALERT "Time-based OTP failed to register a major number\n");
        return majorNumber;
    }

    // Create the device class
    otpClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(otpClass)) {
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class for Time-based OTP\n");
        return -1;
    }

    // Register the device driver
    otpTimeDevice = device_create(otpClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(otpTimeDevice)) {
        class_destroy(otpClass);
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device for Time-based OTP\n");
        return -1;
    }

    printk(KERN_INFO "Time-based OTP: device class created correctly\n");
    return 0;
}

void __exit time_otp_exit(void) {
    device_destroy(otpClass, MKDEV(majorNumber, 0)); // Remove the device
    class_unregister(otpClass); // Unregister the device class
    class_destroy(otpClass); // Remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME); // Unregister the major number
    printk(KERN_INFO "Time-based OTP: Exiting\n");
}


/**
 * @brief Calculates and returns the current counter value.
 * @return Current counter value.
 */
unsigned long get_current_counter(void) {
    unsigned long counter = (unsigned long)(ktime_get_real_seconds() / totp_time_step);
    printk(KERN_INFO "Current counter: %lu\n", counter);
    return counter;
}

/**
 * Safely updates the TOTP secret key.
 * 
 * @param new_key The new key to be used for TOTP generation.
 * @param len The length of the new key.
 * @return Zero on success, non-zero otherwise.
 */
static int update_totp_secret(const char *new_key, size_t len) {
    // Ensure the new key length is within our allowed bounds
    if (len >= TOTP_MAX_SECRET_KEY_SIZE) {
        printk(KERN_WARNING "Time-based OTP: Provided key is too long.\n");
        return -EFAULT;
    }

    mutex_lock(&totp_key_mutex);
    memset(totp_secret_key, 0, TOTP_MAX_SECRET_KEY_SIZE); 
    strncpy(totp_secret_key, new_key, len);
    totp_secret_key_size = len;
    mutex_unlock(&totp_key_mutex);
    printk(KERN_INFO "Time-based OTP: Secret key updated successfully.\n");
    return 0;
}

/**
 * Safely updates the TOTP time step.
 * 
 * @param new_time_step The new time step to be used for TOTP generation.
 * @return Zero on success, non-zero otherwise.
 */
static int update_totp_time_step(unsigned int new_time_step) {
    // Basic validation of the new time step; adjust conditions as necessary
    if (new_time_step < 10 || new_time_step > 60) {
        printk(KERN_WARNING "Time-based OTP: Provided time step is out of allowed range.\n");
        return -EINVAL;
    }

    mutex_lock(&totp_key_mutex);
    totp_time_step = new_time_step;
    mutex_unlock(&totp_key_mutex);

    printk(KERN_INFO "Time-based OTP: Time step updated to %u seconds.\n", new_time_step);
    return 0;
}

static int hmac_sha1(const unsigned char *key, unsigned int keylen, const unsigned char *data, unsigned int datalen, unsigned char *digest) {
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    int ret;

    // Allocate a transformation context for HMAC-SHA1
    tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate transformation context for hmac(sha1): %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    // Allocate descriptor
    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash) {
        crypto_free_shash(tfm);
        printk(KERN_ERR "Failed to allocate shash descriptor\n");
        return -ENOMEM;
    }

    shash->tfm = tfm;
    // Note: No 'flags' assignment is necessary based on the kernel version's requirements

    // Set the HMAC key
    ret = crypto_shash_setkey(tfm, key, keylen);
    if (ret) {
        printk(KERN_ERR "crypto_shash_setkey() failed: %d\n", ret);
        goto out;
    }

    // Perform the HMAC operation directly on the given data
    ret = crypto_shash_digest(shash, data, datalen, digest);
    if (ret) {
        printk(KERN_ERR "crypto_shash_digest() failed: %d\n", ret);
    }

out:
    kfree(shash);
    crypto_free_shash(tfm);
    return ret;
}

/**
 * @brief Generates a Time-based One-Time Password (TOTP).
 * @return Generated TOTP.
 */
unsigned int generate_totp(void) {
    unsigned char digest[SHA1_DIGEST_SIZE];
    unsigned long counter;
    unsigned int otp = 0;
    int ret;
    unsigned int mod_base = 1;
    int i = 0;

    counter = get_current_counter();
    counter = cpu_to_be64(counter); // convert little endian to big endian and no-op on big endian

    ret = hmac_sha1(totp_secret_key, totp_secret_key_size, (unsigned char *)&counter, sizeof(counter), digest);
    if (ret) {
        printk(KERN_ERR "HMAC-SHA1 failed: %d\n", ret);
        return 0;
    }

    // Static truncation (as oppose to the dynamic one in RFC6238) and modular reduction to fit the OTP size
    otp = (digest[10] & 0x7f) << 24 | (digest[11] & 0xff) << 16 | (digest[12] & 0xff) << 8 | (digest[13] & 0xff);
    //otp %= (unsigned int)pow(10, TOTP_DIGITS);
    while (i < TOTP_DIGITS) {
        mod_base *= 10;
        i++;
    }
    otp %= mod_base;
    return otp;
}

static int dev_open(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "Time-based OTP device has been opened\n");
    return 0;
}

static int dev_release(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "Time-based OTP device has been closed\n");
    return 0;
}


static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    char temp_buffer[10]; // 6 digits + null terminator + 3 extra bytes for safety
    unsigned int totp;
    int error_count;
    
    // Check if we've already sent the current TOTP to the user
    if (*offset > 0) {
        return 0;
    }

    // Generate the TOTP
    totp = generate_totp();
    snprintf(temp_buffer, sizeof(temp_buffer), "%06u", totp);
    error_count = copy_to_user(buffer, temp_buffer, strlen(temp_buffer));

    // Check if the copy_to_user operation failed
    if (error_count == 0) {
        *offset = strlen(temp_buffer);
        return *offset;
    } else {
        printk(KERN_INFO "Failed to send TOTP to the user\n");
        return -EFAULT;
    }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    char write_data[64];
    unsigned int new_step;
    ssize_t ret;

    if (len > sizeof(write_data) - 1) {
        printk(KERN_WARNING "Time-based OTP: Write data is too long.\n");
        return -EFAULT;
    }

    if (copy_from_user(write_data, buffer, len)) {
        printk(KERN_WARNING "Time-based OTP: Error copying data from user.\n");
        return -EFAULT;
    }
    write_data[len] = '\0';

    if (strncmp(write_data, "key:", 4) == 0) {
        // Update the secret key
        ret = update_totp_secret(write_data + 4, len - 4);
    } else if (sscanf(write_data, "step:%u", &new_step) == 1) {
        // Update the time step
        ret = update_totp_time_step(new_step);
    } else {
        printk(KERN_WARNING "Time-based OTP: Unrecognized write operation.\n");
        return -EINVAL;
    }

    if (ret) {
        return ret;
    }
    return len;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hassan ZABATT");
MODULE_AUTHOR("Florent ROSSIGNOL");
MODULE_AUTHOR("Pol-Antoine LOISEAU");
MODULE_DESCRIPTION("Time OTP and simple OTP with dynamic listing.");
MODULE_VERSION("0.4");