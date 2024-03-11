#include <linux/init.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "authentication"
#define CLASS_NAME  "authentication"

#define PASSWORD    "p4ssw0rd"
#define FLAG        "flag{YES!}"
#define FAIL        "FAIL: Not Authenticated!"

MODULE_AUTHOR("ir0nstone");
MODULE_DESCRIPTION("Authentication");
MODULE_LICENSE("GPL");

// setting up the device
int major;
static struct class*  my_class  = NULL;
static struct device* my_device = NULL;

static int authenticated = 0;

static ssize_t auth_read(struct file *filp, char __user *buf, size_t len, loff_t *off) {
    printk(KERN_ALERT "[Auth] Attempting to read flag...");

    if (authenticated) {
        copy_to_user(buf, FLAG, sizeof(FLAG));      // ignoring `len` here
        return 1;
    }

    copy_to_user(buf, FAIL, sizeof(FAIL));
    return 0;
}

static ssize_t auth_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
    char password_attempt[20];

    printk(KERN_ALERT "[Auth] Reading password from user...");

    copy_from_user(password_attempt, buf, count);

    if (!strcmp(password_attempt, PASSWORD)) {
        printk(KERN_ALERT "[Auth] Password correct!");
        authenticated = 1;
        return 1;
    }

    printk(KERN_ALERT "[Auth] Password incorrect!");

    return 0;
}

static struct file_operations fops = {
    .read = auth_read,
    .write = auth_write
};

static int __init auth_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);

    if ( major < 0 )
        printk(KERN_ALERT "[Auth] Error assigning Major Number!");
    
    // Register device class
    my_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(my_class)) {
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "[Auth] Failed to register device class\n");
    }

    // Register the device driver
    my_device = device_create(my_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(my_device)) {
        class_destroy(my_class);
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "[Auth] Failed to create the device\n");
    }

    return 0;
}

static void __exit auth_exit(void) {
    device_destroy(my_class, MKDEV(major, 0));              // remove the device
    class_unregister(my_class);                             // unregister the device class
    class_destroy(my_class);                                // remove the device class
    unregister_chrdev(major, DEVICE_NAME);                  // unregister the major number
    printk(KERN_INFO "[Auth] Closing!\n");
}

module_init(auth_init);
module_exit(auth_exit);
