#include <linux/init.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "authentication_ioctl"
#define CLASS_NAME  "authentication_ioctl"

#define PASSWORD    "p4ssw0rd"
#define FLAG        "flag{YES!}"
#define FAIL        "FAIL: Not Authenticated!"

MODULE_AUTHOR("ir0nstone");
MODULE_DESCRIPTION("Authentication, IOCTL Version");
MODULE_LICENSE("GPL");

// setting up the device
int major;
static struct class*  my_class  = NULL;
static struct device* my_device = NULL;

static int authenticated = 0;

static ssize_t auth_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    char *buf = (char *)arg;

    // if CMD is 0, we're attempting to read the flag
    if (cmd == 0) {
        printk(KERN_ALERT "[Auth] Attempting to read flag...");

        if (authenticated) {
            copy_to_user(buf, FLAG, sizeof(FLAG));      // ignoring `len` here
            return 1;
        }

        copy_to_user(buf, FAIL, sizeof(FAIL));
    }
    // if CMD is 1, we are attempting to write the password
    else if (cmd == 1) {
        char password_attempt[20];

        printk(KERN_INFO "[Auth] Reading password from user...");
        copy_from_user(password_attempt, buf, 10);

        if (!strcmp(password_attempt, PASSWORD)) {
            printk(KERN_ALERT "[Auth] Password correct!");
            authenticated = 1;
            return 1;
        }

        printk(KERN_ALERT "[Auth] Password incorrect!");
    }
    // otherwise, it's an unknown operation!
    else {
        printk(KERN_INFO "[Auth] Unknown Operation!");
    }

    return 0;
}

static struct file_operations fops = {
    .compat_ioctl = auth_ioctl,
    .unlocked_ioctl = auth_ioctl
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
