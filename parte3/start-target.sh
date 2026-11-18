#!/bin/sh
cd /home/zekar/Documents/homework/s5/cs/a4/.lab/alpine
exec qemu-system-x86_64 -m 512 -smp 2 -accel kvm -cpu host -display none \
 -serial stdio -monitor none \
 -cdrom alpine-virt.iso -boot d \
 -netdev socket,id=lan,connect=127.0.0.1:10002 -device virtio-net-pci,netdev=lan
