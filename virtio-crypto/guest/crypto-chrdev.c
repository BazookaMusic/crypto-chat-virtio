/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 * Sotiris Dragonas <sotirisdragonas@gmail.com>
 */

#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"
#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	unsigned long flags;
	int ret;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	int *host_fd;

	struct virtqueue *vq;
	struct scatterlist syscall_type_sg, output_msg_sg, host_fd_sg, *sgs[3];
	unsigned int num_out, num_in;

	debug("Entering");

	//set type of call as open
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(int), GFP_KERNEL);

	//set default return value as -ENODEV == no device
	ret = -ENODEV;
	//set nonseekable
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) 
	{
		debug("Could not find crypto device with %u minor",
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	//contains associated device, host file descriptor, semaphore
	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	//init semaphore as unlocked
	sema_init(&crof->lock, 1);
	filp->private_data = crof;

	//associate virtqueue
	vq = crdev->vq;

	num_out = 0; //num of read scatter lists
	num_in = 0; //num of write scatter lists

	//init scatter lists
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	
	//add output scatter list (backend will read from it)
	sgs[num_out++] = &syscall_type_sg; //read_sg's go first

	//add input scatter list (backend will write to it)
	sg_init_one(&host_fd_sg, host_fd, sizeof(int));
	sgs[num_out + num_in++] = &host_fd_sg;

	//lock virtqueue
	if (down_interruptible(&crof->lock))
	{
		kfree(host_fd);
		kfree(syscall_type);
		kfree(crof);

		return -ERESTARTSYS;
	}

	//add buffers to vq
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	//cause backend interrupt
	virtqueue_kick(vq);
	
	//unlock virtqueue
	up(&crof->lock);

	//poll until data is available
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;

	//data received

	//if returned host_fd is invalid -> FAIL
	if(*host_fd < 0)
	{
			ret = -ENODEV;
			goto fail;
	}

	//save host_fd to crof for later usage
	crof->host_fd = *host_fd;
	ret = 0;

fail:
	//free memory
	kfree(host_fd);
	kfree(syscall_type);

	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	unsigned long flags;
	int ret = 0, err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, host_fd_sg, response_sg, *sgs[3];
	unsigned int num_out, num_in, len;

	int *host_fd;
	int *response;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;

	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;

	//value that will be returned by backend that will contain the result of close
	response = kzalloc(sizeof(*response), GFP_KERNEL);
	*response = -1;

	num_out = 0;
	num_in = 0;

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;
	sg_init_one(&response_sg, response, sizeof(*response));
	sgs[num_out + num_in++] = &response_sg;

	if (down_interruptible(&crof->lock))
	{
		kfree(response);
		kfree(host_fd);
		kfree(syscall_type);

		return -ERESTARTSYS;
	}
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	
	up(&crof->lock);

	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;

	//return response from backend to user
	ret = *response;

	if(*response)
		debug("Error while closing...");

	kfree(crof);
	kfree(response);
	kfree(host_fd);
	kfree(syscall_type);
	debug("Leaving");
	return ret;
}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	unsigned long flags;
	long ret = 0;
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, *sgs[8], host_fd_sg, host_return_val_sg, ioctl_cmd_sg;
	unsigned int num_out, num_in, len;
	unsigned int *syscall_type;

//variables used in every case
	int *host_fd, *host_return_val;
	unsigned int *ioctl_cmd;

//ciocgsession declaration
	unsigned char *session_key = NULL;
	struct session_op *ses_op = NULL, ses_op_backup;
	struct scatterlist session_key_sg, ses_op_sg;
//ciocfsession declaration
	__u32 *ses_id = NULL;
	struct scatterlist ses_id_sg;
//cioccrypt declaration
	struct crypt_op *cr_op = NULL, cr_op_backup;
	unsigned char *src = NULL, *iv = NULL, *dst = NULL;
	struct scatterlist cr_op_sg, src_sg, iv_sg, dst_sg;

	debug("Entering");

	//keep struct backups with correct pointers to send back to user
	cr_op_backup.dst = NULL;
	cr_op_backup.len = 0;

	/**
	* Allocate all data that will be sent to the host.
	**/
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	host_return_val = kzalloc(sizeof(*host_return_val), GFP_KERNEL);
	ioctl_cmd = kzalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL;
	ses_id = kzalloc(sizeof(*ses_id), GFP_KERNEL);

	num_out = 0;
	num_in = 0;

	*host_fd = crof->host_fd;
	*ioctl_cmd = cmd;
	*host_return_val = -1;

	//init common scatterlists
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;
	sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
	sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
	sgs[num_out++] = &ioctl_cmd_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");

		ses_op = kzalloc(sizeof(struct session_op), GFP_KERNEL);
		
		//get ses_op from user (arg points to it)
		if(copy_from_user(ses_op, (struct session_op *)arg, sizeof(struct session_op)))
		{
			debug("copy from user error ses_op");
			return -EFAULT;
		}

		//save backup
		ses_op_backup = *ses_op;

		session_key = kzalloc(ses_op->keylen * sizeof(unsigned char), GFP_KERNEL);
		
		//get session key from user
		//cannot get it directly from ses_op->key, because it points to user space
		if(copy_from_user(session_key, ses_op->key, ses_op->keylen * sizeof(unsigned char)))
		{
			debug("copy from user error session_key");
			return -EFAULT;
		}

		sg_init_one(&session_key_sg, session_key, sizeof(*session_key));
		sgs[num_out++] = &session_key_sg;
		sg_init_one(&ses_op_sg, ses_op, sizeof(*ses_op));
		sgs[num_out + num_in++] = &ses_op_sg;

		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");

		//get session id from user (arg points to it)
		if(copy_from_user(ses_id, (__u32 *)arg, sizeof(__u32)))
		{
			debug("copy from user error ses_id");
			return -EFAULT;
		}

		sg_init_one(&ses_id_sg, ses_id, sizeof(*ses_id));
		sgs[num_out++] = &ses_id_sg;

		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");

		cr_op = kzalloc(sizeof(struct crypt_op), GFP_KERNEL);

		//get crypt_op from user (arg points to it)
		if(copy_from_user(cr_op, (struct crypt_op *)arg, sizeof(struct crypt_op)))
		{
			debug("copy from user error cr_op");
			return -EFAULT;
		}

		//keep backup of crypt_op
		cr_op_backup = *cr_op;

		src = kzalloc(cr_op->len * sizeof(*src), GFP_KERNEL);
		iv = kzalloc(VIRTIO_CRYPTO_BLOCK_SIZE * sizeof(*iv), GFP_KERNEL);
		dst = kzalloc(cr_op->len * sizeof(*dst), GFP_KERNEL);

		//get src from user
		if(copy_from_user(src, cr_op->src, cr_op->len * sizeof(unsigned char)))
		{
			debug("copy from user error src");
			return -EFAULT;
		}

		//get iv from user
		if(copy_from_user(iv, cr_op->iv, VIRTIO_CRYPTO_BLOCK_SIZE * sizeof(unsigned char)))
		{
			debug("copy from user error iv");
			return -EFAULT;
		}

		sg_init_one(&cr_op_sg, cr_op, sizeof(struct crypt_op));
		sgs[num_out++] = &cr_op_sg;
		sg_init_one(&src_sg, src, cr_op->len * sizeof(unsigned char));
		sgs[num_out++] = &src_sg;
		sg_init_one(&iv_sg, iv, VIRTIO_CRYPTO_BLOCK_SIZE * sizeof(unsigned char));
		sgs[num_out++] = &iv_sg;
		sg_init_one(&dst_sg, dst, cr_op->len * sizeof(unsigned char));
		sgs[num_out + num_in++] = &dst_sg;

		break;

	default:
		debug("Unsupported ioctl command");
		goto exit_ioctl;
	}

	sgs[num_out + num_in++] = &host_return_val_sg;

	/**
	 * Wait for the host to process our data.
	 **/

	if (down_interruptible(&crof->lock))
		return -ERESTARTSYS;
	
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	
	up(&crof->lock);

	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;

	//data received

	switch (cmd)
	{
		//start session
		case CIOCGSESSION:
			//copy ses_id to ses_op_backup to send it back to user
			ses_op_backup.ses = ses_op->ses;

			//send back ses_op to user with correct user pointers (arg points to user ses_op)
			if(copy_to_user((struct session_op *)arg, &ses_op_backup, sizeof(struct session_op)))
			{
				debug("copy to user error arg");
				return -EFAULT;
			}

			kfree(session_key);
			kfree(ses_op);
			break;
		case CIOCFSESSION:
			break;
		case CIOCCRYPT:
		//encrypt / decrypt operation

			//send dst back to user (cr_op_backup.dst points to user cr_op.dst)
			if(copy_to_user(cr_op_backup.dst, dst, cr_op_backup.len * sizeof(unsigned char)))
			{
				debug("copy to user error dst");
				return -EFAULT;
			}

			kfree(dst);
			kfree(iv);
			kfree(src);
			kfree(cr_op);
			kfree(ses_id);
			break;
	}

	exit_ioctl:
		//forward backend return value to user 
		ret = *host_return_val;

		kfree(syscall_type);
		kfree(host_fd);
		kfree(ioctl_cmd);
		kfree(host_return_val);

		debug("Leaving");

		return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf,
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops =
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;

	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
