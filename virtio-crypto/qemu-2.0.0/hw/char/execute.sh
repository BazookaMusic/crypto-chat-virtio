#!/bin/bash

cd /home/user/cryptodev
insmod cryptodev.ko
cd /home/user/qemu-2.0.0
make
make install
cd /home/user/utopia
./utopia_device.sh

