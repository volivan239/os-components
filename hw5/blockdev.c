#include <linux/module.h>     /* Для всех модулей */
#include <linux/kernel.h>     /* KERN_INFO */
#include <linux/init.h>       /* Макросы */
#include <linux/fs.h>         /* Макросы для устройств */
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ivan Volkov");
MODULE_DESCRIPTION("Sample block device");
MODULE_VERSION("0.1");

#define DEV_NAME                     "blockdev"
#define KERNEL_SECTOR_SIZE           512
#define NR_SECTORS                   1024

int major = 0;

static struct my_block_dev {
    struct gendisk *gd;
	struct request_queue *queue; 
	struct blk_mq_tag_set tag_set;
	spinlock_t lock;
	char *data;
} dev;

static blk_status_t my_block_request(struct blk_mq_hw_ctx *hctx,
                                     const struct blk_mq_queue_data *bd)
{
	printk(KERN_INFO "Visited block request\n");
	struct request *rq = bd->rq;
    struct my_block_dev *dev = rq->q->queuedata;

    blk_mq_start_request(rq);

    if (blk_rq_is_passthrough(rq)) {
        printk (KERN_NOTICE "Skip non-fs request\n");
        blk_mq_end_request(rq, BLK_STS_IOERR);
        goto out;
    }

	struct bio_vec bvec;
    struct req_iterator iter;
    size_t pos = blk_rq_pos(rq) * KERNEL_SECTOR_SIZE;
    size_t dev_size = NR_SECTORS * KERNEL_SECTOR_SIZE;

	rq_for_each_segment(bvec, rq, iter)
	{
		size_t offset = bvec.bv_offset;
		char *buf = kmap_atomic(bvec.bv_page) + offset;
		size_t len = bvec.bv_len;
		if (pos + len > dev_size) {
			len = dev_size - pos;
		}
		printk(KERN_INFO "Request for transmition of %lu bytes (type %d), pos = %lu", len, rq_data_dir(rq), pos);
		if (rq_data_dir(rq)) {
			memcpy(dev->data + pos, buf, len);
		} else {
			memcpy(buf, dev->data + pos, len);
		}
		kunmap_atomic(buf);

		pos += len;
		printk(KERN_INFO "Success transmition of %lu bytes (type %d)", len, rq_data_dir(rq));
	}
    blk_mq_end_request(rq, BLK_STS_OK);

out:
    return BLK_STS_OK;
}

static int my_block_open(struct gendisk *bdev, blk_mode_t mode)
{
    return 0;
}

static void my_block_release(struct gendisk *gd)
{
    return;
}

struct block_device_operations my_block_ops = {
    .owner = THIS_MODULE,
    .open = my_block_open,
    .release = my_block_release
};

static struct blk_mq_ops my_queue_ops = {
   .queue_rq = my_block_request,
};

static int __init blockdev_start(void)
{
    major = register_blkdev(0, DEV_NAME);
    if (major < 0) {
		printk(KERN_ERR "unable to register block device\n");
		return -EBUSY;
    } else {
		printk(KERN_INFO "registered block device, major = %d", major);
	}

	dev.tag_set.ops = &my_queue_ops;
    dev.tag_set.nr_hw_queues = 1;
    dev.tag_set.queue_depth = 128;
    dev.tag_set.numa_node = NUMA_NO_NODE;
    dev.tag_set.cmd_size = 0;
    dev.tag_set.flags = BLK_MQ_F_SHOULD_MERGE;// | BLK_MQ_F_SG_MERGE;
	dev.tag_set.driver_data = &dev;
    int status = blk_mq_alloc_tag_set(&dev.tag_set);
    if (status) {
		printk(KERN_ERR "Failed to allocate tag set");
        return -ENOMEM;
    }
	printk(KERN_INFO "Set device tag_set\n");

	dev.gd = blk_alloc_disk(NUMA_NO_NODE);
	if (dev.gd == NULL) {
		printk(KERN_ERR "failed to allocate disk\n");
		return -ENOMEM;
	}
	dev.queue = dev.gd->queue; 

	status = blk_mq_init_allocated_queue(&dev.tag_set, dev.queue);
    if (status < 0) {
        blk_mq_free_tag_set(&dev.tag_set);
		printk(KERN_ERR "Failed to initialize queue");
		return -ENOMEM;
    }
	blk_queue_logical_block_size(dev.queue, KERNEL_SECTOR_SIZE);
  	dev.queue->queuedata = &dev;
	printk(KERN_INFO "Initialized queue\n");

	dev.gd->major = major;
	dev.gd->first_minor = 0;
	dev.gd->minors = 1;
	dev.gd->fops = &my_block_ops;
	dev.gd->private_data = &dev;
	snprintf(dev.gd->disk_name, 32, DEV_NAME);
	set_capacity(dev.gd, NR_SECTORS);
	printk(KERN_INFO "Set device properties\n");

	dev.data = vmalloc(NR_SECTORS * KERNEL_SECTOR_SIZE);
	if (dev.data == NULL) {
		printk(KERN_ERR "Unable to allocate enough memory for device");
		return -ENOMEM;
	}

    status = add_disk(dev.gd);
	printk(KERN_INFO "successfully added block device, status = %d\n", status);

    return 0;
}

static void __exit blockdev_end(void)
{
	if (dev.gd) {
        del_gendisk(dev.gd);
	}
	blk_mq_destroy_queue(dev.queue);
    blk_mq_free_tag_set(&dev.tag_set);
	unregister_blkdev(major, DEV_NAME);
	pr_info("BLOCKDEV: unload\n");
}

module_init(blockdev_start);
module_exit(blockdev_end);
