#!/bin/bash

rmmod virtio_crypto
cd /home/user/virtio
insmod virtio_crypto.ko
./crypto_dev_nodes.sh
