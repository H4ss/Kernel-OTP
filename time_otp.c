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
#define CLASS_NAME "otp"
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


unsigned long get_current_counter(void) {
    return (unsigned long)(ktime_get_real_seconds() / totp_time_step);
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
    if (len >= TOTP_SECRET_KEY_SIZE) {
        printk(KERN_WARNING "Time-based OTP: Provided key is too long.\n");
        return -EFAULT;
    }

    // Lock the mutex before updating the key
    mutex_lock(&totp_key_mutex);

    // Clear the existing key
    memset(totp_secret_key, 0, TOTP_SECRET_KEY_SIZE);
    
    // Copy the new key
    strncpy(totp_secret_key, new_key, len);
    totp_secret_key_length = len;

    // Unlock the mutex after updating the key
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

static int hmac_sha1(const unsigned char *key, unsigned int keylen,
                     const unsigned char *data, unsigned int datalen,
                     unsigned char *digest) {
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    int ret;

    tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate transform for hmac(sha1): %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }
    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash) {
        crypto_free_shash(tfm);
        printk(KERN_ERR "Failed to allocate shash_desc\n");
        return -ENOMEM;
    }
    shash->tfm = tfm;
    shash->flags = 0x0;
    if ((ret = crypto_shash_setkey(tfm, key, keylen))) {
        printk(KERN_ERR "crypto_shash_setkey() failed: %d\n", ret);
        goto out;
    }
    sg_init_one(&sg[0], data, datalen);
    if ((ret = crypto_shash_digest(shash, sg, datalen, digest))) {
        printk(KERN_ERR "crypto_shash_digest() failed: %d\n", ret);
    }

out:
    kfree(shash);
    crypto_free_shash(tfm);
    return ret;
}

unsigned int generate_totp(void) {
    unsigned char digest[SHA1_DIGEST_SIZE];
    unsigned long counter;
    unsigned int otp = 0;
    int ret;

    counter = get_current_counter();
    counter = cpu_to_be64(counter); // convert little endian to big endian and no-op on big endian

    ret = hmac_sha1(totp_secret_key, totp_secret_key_size, (unsigned char *)&counter, sizeof(counter), digest);
    if (ret) {
        printk(KERN_ERR "HMAC-SHA1 failed: %d\n", ret);
        return 0;
    }

    // Static truncation (as oppose to the dynamic one in RFC6238) and modular reduction to fit the OTP size
    otp = (digest[19] & 0x7f) << 24 | (digest[20] & 0xff) << 16 | (digest[21] & 0xff) << 8 | (digest[22] & 0xff);
    otp %= (unsigned int)pow(10, TOTP_DIGITS);

    printk(KERN_INFO "Generated TOTP: %u\n", otp);
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
    // Temporary buffer to hold the TOTP as a string
    char temp_buffer[10]; // Large enough for a null-terminated 6-digit TOTP
    unsigned int totp;
    int error_count;
    
    // Check if we've already sent the current TOTP to the user
    if (*offset > 0) {
        // The TOTP has already been read, indicating we're done
        return 0;
    }

    // Generate the current TOTP (the function you defined earlier)
    totp = generate_totp();

    // Convert the TOTP to a string (ensure temp_buffer is large enough)
    snprintf(temp_buffer, sizeof(temp_buffer), "%06u", totp);

    // Copy the string to user space
    error_count = copy_to_user(buffer, temp_buffer, strlen(temp_buffer));

    // If there's an error copying to user space, return an error
    if (error_count == 0) {
        // Update the offset to indicate we've sent the TOTP
        *offset = strlen(temp_buffer);
        return *offset; // Return the number of bytes sent
    } else {
        printk(KERN_INFO "Failed to send TOTP to the user\n");
        return -EFAULT; // Return a bad address message
    }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    char write_data[64]; // Temporary buffer for write data
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
    write_data[len] = '\0'; // Ensure null-termination

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