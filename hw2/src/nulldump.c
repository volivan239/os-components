#include <linux/module.h>     /* Для всех модулей */
#include <linux/kernel.h>     /* KERN_INFO */
#include <linux/init.h>       /* Макросы */
#include <linux/fs.h>         /* Макросы для устройств */
#include <linux/cdev.h>	      /* Функции регистрации символьных устройств */
#define BUF_SIZE 512

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ivan Volkov");
MODULE_DESCRIPTION("Nulldump -- /dev/null + dump");
MODULE_VERSION("0.1");

static ssize_t nulldump_read(struct file *file, char __user *buf, size_t len, loff_t *off)
{
	pr_info("NULLDUMP: read %lu bytes\n", len);
	return 0;
}

static ssize_t nulldump_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	// static const int BUF_SIZE = 1024;

	char kbuf[BUF_SIZE];
	char hexdump[2 * BUF_SIZE + 1];

	for (size_t i = 0; i < len; i += BUF_SIZE) {
		size_t curlen = BUF_SIZE;
		if (len - i < BUF_SIZE) {
			curlen = len - i;
		}

		if (copy_from_user(kbuf, buf + i, curlen))
		{
			return -EFAULT;
		}

		for (size_t i = 0; i < curlen; i++)
		{
			snprintf(hexdump + 2 * i, 3, "%02hhx", kbuf[i]);
		}

		if (i == 0) {
			pr_info("NULLDUMP: write of %lu bytes by pid=%d, cmd=%s, data=0x%s", len, current->pid, current->comm, hexdump);
		} else {
			printk(KERN_CONT "%s", hexdump);
		}
	}
	printk(KERN_CONT "\n");
	return len;
}

static int nulldump_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

static struct file_operations nulldump_ops =
{
	.owner      = THIS_MODULE,
	.read       = nulldump_read,
	.write      = nulldump_write,
};

dev_t dev = 0;
static struct cdev nulldump_cdev;
static struct class *nulldump_class;

static int __init nulldump_start(void)
{
	int res;

	if ((res = alloc_chrdev_region(&dev, 0, 1, "nulldump")) < 0)
	{
		pr_err("Error allocating major number\n");
		return res;
	}
	pr_info("NULLDUMP load: Major = %d Minor = %d\n", MAJOR(dev), MINOR(dev));
        
	cdev_init(&nulldump_cdev, &nulldump_ops);        
	if ((res = cdev_add(&nulldump_cdev, dev, 1)) < 0)
    {
		pr_err("NULLDUMP: device registering error\n");
		unregister_chrdev_region (dev, 1);
		return res;
	}        
        
	if (IS_ERR(nulldump_class = class_create ("nulldump_class")))
	{
		cdev_del(&nulldump_cdev);
		unregister_chrdev_region(dev, 1);
		return -1;
	}

    nulldump_class->dev_uevent = nulldump_uevent;
	
	if (IS_ERR(device_create(nulldump_class, NULL, dev, NULL, "nulldump")))
	{
		pr_err("NULLDUMP: error creating device\n");
		class_destroy(nulldump_class);
		cdev_del(&nulldump_cdev);
		unregister_chrdev_region(dev, 1);
		return -1;
	}
        
    return 0;
}

static void __exit nulldump_end(void)
{
	device_destroy(nulldump_class, dev);
	class_destroy(nulldump_class);
	cdev_del(&nulldump_cdev);
	unregister_chrdev_region(dev, 1);
	pr_info("NULLDUMP: unload\n");
}

module_init(nulldump_start);
module_exit(nulldump_end);
