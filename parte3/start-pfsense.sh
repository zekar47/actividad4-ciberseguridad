#!/bin/sh
cd /home/zekar/Documents/homework/s5/cs/a4/.lab/pfsense
exec qemu-system-x86_64 -m 2048 -smp 2 -accel kvm -cpu host -display none \
 -serial stdio -monitor none \
 -drive file=pfSense.qcow2,format=qcow2,if=none,id=target \
 -device virtio-blk-pci,drive=target,bootindex=0 \
 -netdev user,id=wan -device virtio-net-pci,netdev=wan \
 -netdev user,id=mgmt,net=192.168.1.0/24,hostfwd=tcp:127.0.0.1:8443-192.168.1.1:443 -device virtio-net-pci,netdev=mgmt \
 -netdev socket,id=opt1,listen=127.0.0.1:10001 -device virtio-net-pci,netdev=opt1 \
 -netdev socket,id=opt2,listen=127.0.0.1:10002 -device virtio-net-pci,netdev=opt2
