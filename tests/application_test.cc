#include <cstdarg>
#include <cstdlib>
#include <gtest/gtest.h>

#include "application.h"

namespace {
typedef struct args {
    int argc;
    char **argv;

    args(int argc, ...)
    {
        this->argc = argc;
        this->argv = static_cast<char **>(malloc(argc * sizeof(const char *)));
        assert(this->argv != nullptr && "malloc() failed");

        auto tmp = this->argv;
        va_list args_list;
        va_start(args_list, argc);
        for (int i = 0; i < argc; ++i) {
            *tmp++ = (char *)va_arg(args_list, const char *);
        }

        va_end(args_list);
    }
    ~args()
    {
        if (!this->argv) {
            auto tmp = this->argv;
            for (int i = 0; i <= argc; ++i) {
                free(*tmp++);
            }
        }
    }
} args;
args create_comm{8, "mydocker", "create", "-b", ".", "--pid-file", "/tmp/pid", "--no-pivot", "true"};
args run_comm{4, "mydocker", "run", "-b", "."};

class ApplicationTest : public testing::Test {
private:
};

TEST_F(ApplicationTest, ApplicationTest)
{
    mydocker::app::application app_create;
    mydocker::app::application app_run;

    ASSERT_EQ(app_create.run(create_comm.argc, create_comm.argv), 0);
    ASSERT_EQ(app_run.run(run_comm.argc, run_comm.argv), 0);
}
}; // namespace
