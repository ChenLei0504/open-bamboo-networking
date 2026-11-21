// Unit tests for MQTT URL scheme helpers (brtc://, file://, ftp://).

#include "obn/bambu_networking.hpp"
#include "obn/print_job.hpp"

#include <cassert>
#include <iostream>
#include <string>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": " #cond "\n"; \
        return 1; \
    } \
} while (0)

int main()
{
    CHECK(obn::print_job::build_brtc_emmc_url("foo.gcode.3mf")
          == "brtc://emmc/foo.gcode.3mf");
    CHECK(obn::print_job::build_brtc_emmc_url("/foo.gcode.3mf")
          == "brtc://emmc/foo.gcode.3mf");

    CHECK(obn::print_job::build_file_url("/media/usb0/foo.gcode.3mf")
          == "file:///media/usb0/foo.gcode.3mf");
    CHECK(obn::print_job::build_file_url("media/usb0/foo.gcode.3mf")
          == "file:///media/usb0/foo.gcode.3mf");

    CHECK(obn::print_job::build_ftp_url("/foo.gcode.3mf")
          == "ftp://foo.gcode.3mf");
    CHECK(obn::print_job::build_ftp_url("foo.gcode.3mf")
          == "ftp://foo.gcode.3mf");

    // Spaces stay raw in the dispatched URL: firmware matches the STOR name
    // literally and rejects %20 with 83902467 (unable to parse the file).
    CHECK(obn::print_job::build_ftp_url("/Pre-filter V6b X1C x6.gcode.3mf")
          == "ftp://Pre-filter V6b X1C x6.gcode.3mf");
    CHECK(obn::print_job::build_ftp_url("cache/a b.gcode.3mf")
          == "ftp://cache/a b.gcode.3mf");
    CHECK(obn::print_job::build_ftp_url("plain.gcode.3mf")
          == "ftp://plain.gcode.3mf");

    BBL::PrintParams p{};
    p.try_emmc_print = true;
    CHECK(obn::print_job::use_brtc_cache_upload(p));
    p.try_emmc_print = false;
    CHECK(!obn::print_job::use_brtc_cache_upload(p));

    std::cout << "print_url_test: ok\n";
    return 0;
}
