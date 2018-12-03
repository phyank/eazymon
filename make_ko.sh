#! bin/bash
cd hook_syscalls_src
make
rm ../hook_syscalls.ko
cp hook_syscalls.ko ../hook_syscalls.ko
cd ../
