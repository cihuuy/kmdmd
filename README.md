#  Rootkit Project

## Introduction

This project is a rootkit development. It is designed as a kernel module that demonstrates various rootkit techniques on Linux systems. The rootkit is capable of hiding files, processes, and itself from system tools, intercepting system calls, and manipulating process signals.

**Warning**: This rootkit is intended for educational purposes only. Use it at your own risk and only in environments where you have permission to do so. Improper use of this rootkit can lead to ethical concerns and potential legal issues.

# References

1. https://xcellerator.github.io/posts/linux_rootkits_01/
2. https://github.com/xcellerator/linux_kernel_hacking
3. https://blog.csdn.net/whatday/article/details/102488130
4. https://blog.csdn.net/weixin_45030965/article/details/129212657
5. chatGPT

## Features

- **File Hiding**: Dynamically hides specified files from the file system, making them invisible to user-level queries.
- **Process Masquerading**: Changes the names of processes to disguise their true nature.
- **Module Hiding**: Hides the rootkit module from the `lsmod` command, making detection more difficult.
- **Signal Interception**: Captures and blocks specific signals sent to processes, such as SIGKILL, to prevent the termination of protected processes.
- **System Call Interception**: Hooks into system calls to monitor or alter system behavior dynamically.

## Prerequisites

- A Linux environment with kernel development tools installed (`build-essential`, `linux-headers-$(uname -r)`).
- Basic knowledge of loading and unloading kernel modules (`insmod`, `rmmod`).

## Compilation

To compile the rootkit, navigate to the root directory of the project and run:

```
make
```

This will generate a `rootkit.ko` file, which is the loadable kernel module.

## Loading the Rootkit and setup the /dev/rootkit

Load the rootkit into the kernel using the following command:

```
sudo insmod rootkit.ko
sudo mknod /dev/rootkit c 509 0 # change the 509 to your major number
```

**Note**: You must have root privileges to load kernel modules.

## Usage

After loading the rootkit, you can interact with it through a user-space application that makes IOCTL calls to the rootkit's device file. The IOCTL commands allow you to enable or disable the rootkit's features dynamically.

compile the main.c file and execute a.out

```
gcc main.c
sudo ./a.out
```

Upon execution, the application will prompt you to enter a choice corresponding to the action you wish to perform:

1. **IOCTL_MOD_HOOK**: Activate or deactivate a specific kernel hook.
2. **IOCTL_MOD_HIDE**: Toggle the visibility of the rootkit module itself.
3. **IOCTL_MOD_MASQ**: Masquerade a process by changing its name.
4. **IOCTL_FILE_HIDE**: Hide a specific file from the file system.

### Example Usage

To hide a file named `test2.c`, you would run the `rootkit_controller` application and enter `4` when prompted for a choice. The application will then send an IOCTL request to the rootkit to hide the specified file, and use `ls` to check the file whether is hided or not.

If you want to test sys_kill and sys_reboot and hide file, you can use the following process and command to check the process state and pid.

```
# Check out the test process when testing IOCTL_MOD_MASQ
ps ao pid,comm

ps aux | grep test

# reboot command for testing IOCTL_MOD_HOOK
sudo systemctl --force --force poweroff

# check the rootkit module
lsmod | head
```

**Note**: Because I am using UTM to build the environment, so we need to execute `sudo systemctl --force --force poweroff` rather than reboot.

### Note

Ensure that the rootkit module is loaded into the kernel before attempting to use the `a.out` application. The application requires `/dev/rootkit` device file to be present, which is created by the rootkit module upon loading.

### Exiting the Application

To exit the application, enter `0` when prompted for a choice. This will close the application and release any resources it was using.

## Remove the Rootkit and /dev/rootkit

```
sudo rmmod rootkit && sudo rm /dev/rootkit
```

## rootkit.c development

The rootkit provides a set of IOCTL commands that allow user-space applications to interact with it. These commands enable the activation of the rootkit's various features. Here's a breakdown of each IOCTL command implemented in the `rootkit_ioctl` function:

### IOCTL_MOD_HOOK

This command is used to activate or deactivate specific kernel hooks. When this IOCTL command is received, the rootkit will either install or remove the hooks based on the current state. This allows for dynamic control over which system calls are being monitored or modified by the rootkit.

Implementation details:

- The rootkit checks if the system call table address is already obtained. If not, it retrieves the address using the `get_syscall_table` function.
- It then saves the original system call addresses for `kill` and `reboot` functions.
- The system call table entries for `kill` and `reboot` are replaced with addresses of the rootkit's custom functions (`hook_kill` and `hook_reboot`), effectively hooking these system calls.

### IOCTL_MOD_HIDE

This command toggles the visibility of the rootkit module itself. When activated, the rootkit removes itself from the list of loaded modules, making it invisible to commands like `lsmod`. This is achieved by manipulating the module's list entry in the kernel's module list.

Implementation details:

- The rootkit checks if it is currently hidden. If not, it saves the current position in the module list and then removes itself from the list, effectively hiding the module.
- To unhide, the rootkit re-inserts itself into the saved position in the module list.

### IOCTL_MOD_MASQ

This command allows for the masquerading of a process by changing its name. It is useful for disguising malicious processes under innocuous names.

Implementation details:

- The rootkit receives a structure containing the original process name and the new name it should be changed to.
- It iterates over all running processes and compares their names with the provided original name.
- If a match is found, the process name is changed to the new name.

### IOCTL_FILE_HIDE

This command hides a specified file from directory listings. It works by hooking the `getdents64` system call and filtering out the directory entry of the specified file.

Implementation details:

- The rootkit receives the name of the file to be hidden.
- It hooks the `getdents64` system call and in the custom `hook_getdents64` function, it filters out any directory entries that match the specified file name, effectively hiding the file from listings.

