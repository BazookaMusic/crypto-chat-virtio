/*
 * Virtio Crypto Device
 *
 * Implementation of virtio-crypto qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 * Sotiris Dragonas <sotirisdragonas@gmail.com>
 */

#include <qemu/iov.h>
#include "hw/virtio/virtio-serial.h"
#include "hw/virtio/virtio-crypto.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

#define BLOCK_SIZE	16

static uint32_t get_features(VirtIODevice *vdev, uint32_t features)
{
	DEBUG_IN();
	return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
	DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
	DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
	VirtQueueElement elem;
	unsigned int *syscall_type;
	int *host_fd;
	int *return_val;
	unsigned int *cmd;
	unsigned char *session_key;
	struct session_op *ses_op;
	__u32 *ses_id;
	struct crypt_op *cr_op;
	unsigned int *src, *iv, *dst;

	DEBUG_IN();

	//remove element from queue if it exists
	if (!virtqueue_pop(vq, &elem)) {
		DEBUG("No item to pop from VQ :(");
		return;
	}

	DEBUG("I have got an item from VQ :)");

	//get system call type from frontend scatter gather list
	syscall_type = elem.out_sg[0].iov_base;
	switch (*syscall_type) 
	{
		//open system call
		case VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN:
			DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN");

			host_fd = elem.in_sg[0].iov_base;
			//call open and return host file descriptor to frontend
			*host_fd = open("/dev/crypto", O_RDWR);

			break;

		//close system call
		case VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE:
			DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE");

			host_fd = elem.out_sg[1].iov_base;

			return_val = elem.in_sg[0].iov_base;
			//call close and return value to frontend for error checking
			*return_val = close(*host_fd);

			break;

		//ioctl call 
		case VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL:
			DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL");

			//get host_fd and command
			host_fd = elem.out_sg[1].iov_base;
			cmd = elem.out_sg[2].iov_base;

			switch (*cmd) 
			{
				//start crypto session
				case CIOCGSESSION:

					//get session key from frontend
					session_key = elem.out_sg[3].iov_base;
					ses_op = elem.in_sg[0].iov_base;
					return_val = elem.in_sg[1].iov_base;

					//connect ses_op->key with session_key from frontend
					ses_op->key = session_key;

					//return updated session_op and return_value
					if ((*return_val = ioctl(*host_fd, CIOCGSESSION, ses_op)))
					{
						perror("ioctl(CIOCGSESSION)");
					}

					break;

				//finish session
				case CIOCFSESSION:

					//get session_id, run ioctl and return return_value
					ses_id = elem.out_sg[3].iov_base;
					return_val = elem.in_sg[0].iov_base;

					if((*return_val = ioctl(*host_fd, CIOCFSESSION, ses_id)))
					{
						perror("ioctl(CIOCFSESSION)");
					}

					break;

				//encrypt-decrypt 	
				case CIOCCRYPT:

					//read source, iv and call ioctl for encryption/decryption
					//data is returned to frontend through dst
					cr_op = elem.out_sg[3].iov_base;
					src = elem.out_sg[4].iov_base;
					iv = elem.out_sg[5].iov_base;
					dst = elem.in_sg[0].iov_base;
					return_val = elem.in_sg[1].iov_base;

					cr_op->src = src;

					cr_op->iv = iv;

					cr_op->dst = dst;

					if((*return_val = ioctl(*host_fd, CIOCCRYPT, cr_op)))
					{
						perror("ioctl(CIOCCRYPT)");
					}

					break;
			}

			break;

		default:
			DEBUG("Unknown syscall_type");
	}

	//push element to vq
	virtqueue_push(vq, &elem, 0);
	//cause frontend interrupt (not used in the current implementation)
	//polling is used instead
	virtio_notify(vdev, vq);
}

static void virtio_crypto_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

	DEBUG_IN();

    virtio_init(vdev, "virtio-crypto", 13, 0);
	virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_crypto_unrealize(DeviceState *dev, Error **errp)
{
	DEBUG_IN();
}

static Property virtio_crypto_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_crypto_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

	DEBUG_IN();
    dc->props = virtio_crypto_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_crypto_realize;
    k->unrealize = virtio_crypto_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_crypto_info = {
    .name          = TYPE_VIRTIO_CRYPTO,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCrypto),
    .class_init    = virtio_crypto_class_init,
};

static void virtio_crypto_register_types(void)
{
    type_register_static(&virtio_crypto_info);
}

type_init(virtio_crypto_register_types)
