# kernel level hackatime (WIP)

**DISCLAIMER: this is not anything officially endorsed by hackatime. if you are a newcomer go to the actual hackatime install page, you do not need to and should not install this.**

this is a linux loadable kernel module that prevents fraud by doing kernel level stuff
## what it does

essentially it tracks if your machine has gotten HID events in the last few seconds and if it hasnt it blocks sending heartbeats to hackatime.

normally wakatime starts queuing heartbeats now since it thinks its offline as network is failing but it also blocks write access to that file that stores offline heartbeats using a BPF LSM hook.

## requirements

- you are using linux (OBVIOUSLY), a docker container wont work, either an actual machine or a full VM.
- all these and im not even gonna try to figure out the names if youre not debian
    ```sh
    sudo apt install clang llvm libbpf-dev bpftool dwarves
    ```
- a linux kernel with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF_MODULES=y`
- headers for your running kernel (`linux-headers-$(uname -r)`)
## installation
if you have all the stuff needed then
```sh
sudo cp /sys/kernel/btf/vmlinux /lib/modules/$(uname -r)/build/
make
sudo insmod hello.co
```

## note
DO NOT ACTUALLY USE THIS ALRIGHT I DO NOT BEAR RESPONSIBILITY IF FRAUD SQUAD BANS YOU
