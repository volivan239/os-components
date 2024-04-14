#include <linux/module.h>     /* Для всех модулей */
#include <linux/kernel.h>     /* KERN_INFO */
#include <linux/init.h>       /* Макросы */
#include <linux/fs.h>         /* Макросы для устройств */
#include <linux/cdev.h>	      /* Функции регистрации символьных устройств */
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ivan Volkov");
MODULE_DESCRIPTION("Membuf");
MODULE_VERSION("0.1");

static size_t buf_size = 2048;
static const size_t BUF_SIZE_MAX = 1 << 30;
static char *buffer = NULL;

DEFINE_RWLOCK(membuf_lock);

static int buf_size_set(const char *val, const struct kernel_param *kp)
{
	size_t new_buf_size = 0;
	int res, ret;

	res = kstrtoul(val, 10, &new_buf_size);
	if (res != 0 || new_buf_size > BUF_SIZE_MAX) {
		ret = -EINVAL;
		goto exit_buf_size_set;
	}

	char *new_buffer = kmalloc(new_buf_size, GFP_KERNEL);
	if (new_buffer == NULL) {
		ret = -ENOMEM;
		goto exit_buf_size_set;
	}

	memset(new_buffer, 0, new_buf_size);

	write_lock(&membuf_lock);

	if (buffer != NULL) {
		size_t min_size = new_buf_size < buf_size ? new_buf_size : buf_size;
		memcpy(new_buffer, buffer, min_size);
		kfree(buffer);
	}
	buffer = new_buffer;
	ret = param_set_int(val, kp);

	write_unlock(&membuf_lock);

	pr_info("SUCCESS old: %lu, new: %lu\n", buf_size, new_buf_size);

exit_buf_size_set:
	return ret;
}

static const struct kernel_param_ops param_ops = {
	.set	= buf_size_set,
	.get	= param_get_int,
};

module_param_cb(membufsize, &param_ops, &buf_size, 0664);

static ssize_t membuf_read(struct file *file, char __user *buf, size_t len, loff_t *off)
{
	ssize_t ret;
	pr_info("MEMBUF: read %lu bytes\n", len);

	char *mid_buf = kmalloc(len, GFP_KERNEL);
	if (mid_buf == NULL) {
		ret = -ENOMEM;
		goto exit_membuf_read_no_unlock;
	}

	read_lock(&membuf_lock);
	if (*off > buf_size) {
		ret = -EINVAL;
		goto exit_membuf_read_unlock;
	}
	if (*off + len > buf_size) {
		len = buf_size - *off;
	}
	memcpy(mid_buf, buffer + *off, len);
	read_unlock(&membuf_lock);

	ret = len - copy_to_user(buf, mid_buf, len);
	pr_info("MEMBUF: success read of %ld bytes\n", ret);
	*off += ret;
	goto exit_membuf_read_no_unlock;

exit_membuf_read_unlock:
	read_unlock(&membuf_lock);
exit_membuf_read_no_unlock:
	return ret;
}

static ssize_t membuf_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	ssize_t ret;

	pr_info("MEMBUF: write %lu bytes\n", len);
	char *mid_buf = kmalloc(len, GFP_KERNEL);
	if (mid_buf == NULL) {
		ret = -ENOMEM;
		goto exit_membuf_write_no_unlock;
	}
	
	ret = len - copy_from_user(mid_buf, buf, len);

	write_lock(&membuf_lock);
	if (*off >= buf_size) {
		ret = -EINVAL;
		goto exit_membuf_write_unlock;
	}
	if (*off + len > buf_size) {
		len = buf_size - *off;
	}
	memcpy(buffer + *off, mid_buf, len);
	write_unlock(&membuf_lock);

	pr_info("MEMBUF: success write of %ld bytes\n", ret);
	*off += ret;
	goto exit_membuf_write_no_unlock;

exit_membuf_write_unlock:
	write_unlock(&membuf_lock);
exit_membuf_write_no_unlock:
	return ret;
}

static int membuf_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

static struct file_operations membuf_ops =
{
	.owner      = THIS_MODULE,
	.read       = membuf_read,
	.write      = membuf_write,
};

dev_t dev = 0;
static struct cdev membuf_cdev;
static struct class *membuf_class;

static int __init membuf_start(void)
{
	int res;

	if ((res = alloc_chrdev_region(&dev, 0, 1, "membuf")) < 0)
	{
		pr_err("Error allocating major number\n");
		return res;
	}
	pr_info("MEMBUF load: Major = %d Minor = %d\n", MAJOR(dev), MINOR(dev));
        
	cdev_init(&membuf_cdev, &membuf_ops);        
	if ((res = cdev_add(&membuf_cdev, dev, 1)) < 0)
    {
		pr_err("MEMBUF: device registering error\n");
		unregister_chrdev_region (dev, 1);
		return res;
	}        
        
	if (IS_ERR(membuf_class = class_create ("membuf_class")))
	{
		cdev_del(&membuf_cdev);
		unregister_chrdev_region(dev, 1);
		return -1;
	}

    membuf_class->dev_uevent = membuf_uevent;
	
	if (IS_ERR(device_create(membuf_class, NULL, dev, NULL, "membuf")))
	{
		pr_err("MEMBUF: error creating device\n");
		class_destroy(membuf_class);
		cdev_del(&membuf_cdev);
		unregister_chrdev_region(dev, 1);
		return -1;
	}

	if (buffer == NULL) {
		buffer = kmalloc(buf_size, GFP_KERNEL);
		if (buffer == NULL) {
			return -1;
		}
		memset(buffer, 0, sizeof(buf_size));
	}
        
    return 0;
}

static void __exit membuf_end(void)
{
	device_destroy(membuf_class, dev);
	class_destroy(membuf_class);
	cdev_del(&membuf_cdev);
	unregister_chrdev_region(dev, 1);
	pr_info("MEMBUF: unload\n");
}

module_init(membuf_start);
module_exit(membuf_end);
