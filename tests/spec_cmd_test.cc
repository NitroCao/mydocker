#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ftw.h>
#include <gtest/gtest.h>
#include <sys/stat.h>

#include "spec_cmd.h"

namespace {
typedef struct args {
    int ret;
    std::string input;
} args;

class SpecCmdTest : public testing::Test {
protected:
    args happy_path;
    args bad_path;
    args existing_path;
    args denied_path;

    void SetUp()
    {
        char temp[] = "/tmp/mydocker.XXXXXX";
        char *d = mkdtemp(temp);
        if (d == nullptr)
            throw std::invalid_argument("mkdtemp() failed");
        temp_dir = std::string(d);

        happy_path.input = temp_dir;
        happy_path.ret = 0;

        bad_path.input = "/non-exist-lala";
        bad_path.ret = ENOENT;

        existing_path.input = temp_dir + "/existing-spec";
        existing_path.ret = 1;
        if (mkdir(existing_path.input.c_str(), 0700) != 0) {
            throw std::invalid_argument("failed to create existing directory");
        }
        std::ofstream existing_spec(existing_path.input + "/config.json");
        if (!existing_spec.is_open())
            throw std::invalid_argument("failed to create existing config.json");

        denied_path.input = "/etc";
        denied_path.ret = EPERM;
    }

    void TearDown()
    {
        if (nftw(temp_dir.c_str(), remove_file, 10, FTW_DEPTH | FTW_MOUNT | FTW_PHYS) != 0) {
            std::cerr << "failed to remove temp dir " << temp_dir << ": " << strerror(errno) << std::endl;
        }
    }

    bool check_file(std::string filename)
    {
        struct stat stat_info;
        if (stat(filename.c_str(), &stat_info) == 0)
            return true;
        else
            return false;
    }

    const std::string &get_temp_dir() { return temp_dir; }

private:
    std::string temp_dir;

    static int remove_file(const char *pathname, const struct stat *sb, int type_flag, struct FTW *ftwbuf)
    {
        if (remove(pathname) != 0) {
            std::cerr << "failed to remove file " << pathname << ": " << strerror(errno) << std::endl;
            return 1;
        }
        return 0;
    }
};

TEST_F(SpecCmdTest, SpecCmdTest)
{
    using namespace mydocker::spec;
    int result;

    result = spec::run(happy_path.input);
    ASSERT_EQ(result, happy_path.ret);
    ASSERT_TRUE(check_file(get_temp_dir() + "/" + mydocker::specs::spec_config));

    result = spec::run(bad_path.input);
    ASSERT_EQ(result, bad_path.ret);

    result = spec::run(existing_path.input);
    ASSERT_EQ(result, existing_path.ret);

    result = spec::run(denied_path.input);
    ASSERT_EQ(result, denied_path.ret);
}
}; // namespace
