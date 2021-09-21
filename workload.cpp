#include <cstring>
#include <iostream>
extern "C"
{
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
}
int main(int argc, char** argv)
{
#pragma omp parallel
    {
        int fd = open("/tmp", O_TMPFILE | O_SYNC | O_RDWR | O_EXCL, S_IRUSR | S_IWUSR);
        if (fd < 0)
        {
            std::cerr << "could not create temporary file: " << strerror(errno) << std::endl;
            exit(1);
        }

#pragma omp barrier
        for (int i = 0; i < 4; i++)
        {
            for (int i = 0; i < 8; i++)
            {
#pragma omp barrier
                usleep(10);
            }
            int ret = fchmod(fd, S_IRUSR | S_IWUSR);
            if (ret < 0)
            {
                std::cerr << "could not fchmod temporary file: " << strerror(errno) << std::endl;
            }
            sleep(10);
        }
    }

    std::cerr << "compute done\n";
}
