# Virtio crypto chat
An end to end encrypted chat cli application for my OSLab 2018 project in NTUA. Uses the cryptodev linux module to encrypt raw text data. Also includes a virtio character device driver for the cryptodev module for faster access when used in a qemu vm.

# Included
    1. sockets, contains the application in two versions (no encryption -z1 postfix and encryption included -z3 postfix)
    2. cryptodev, includes test for the cryptodev module
    3. virtio-crypto, contains changes to be made to qemu installation to support the virtio driver
# Disclaimer
The project is heavily based on a teacher provided skeleton. My implementations include only the application, the character device driver (frontend-guest side) and the virtio driver (backend - host side) 