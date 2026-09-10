//! Compiles the Infineon OPTIGA Trust M host library from the git submodule
//! together with the Linux I2C platform layer. Plain C99 against libc, so a
//! cross build only needs a C compiler for the target triple, which the `cc`
//! crate finds by convention (e.g. `aarch64-linux-musl-gcc`).

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=csrc");

    let lib = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../optiga-trust-m");
    if !lib.join("include/optiga_crypt.h").exists() {
        panic!(
            "Infineon host library not found at {}. Run: git submodule update --init",
            lib.display()
        );
    }
    for d in ["src", "include", "extras/pal/linux"] {
        println!("cargo:rerun-if-changed={}", lib.join(d).display());
    }

    let mut build = cc::Build::new();
    build
        .include("csrc")
        .include(lib.join("include"))
        .include(lib.join("include/pal"))
        .include(lib.join("include/common"))
        .include(lib.join("include/comms"))
        .include(lib.join("include/cmd"))
        .include(lib.join("include/ifx_i2c"))
        .include(lib.join("extras/pal/linux"))
        .include(lib.join("extras/pal/linux/include"))
        .define("OPTIGA_LIB_EXTERNAL", "\"trustm_sys_config.h\"")
        // Kernel UAPI fallbacks for toolchains without <linux/*.h> (bare musl
        // cross compilers). Searched after the system directories.
        .flag("-idirafter")
        .flag("csrc/compat")
        .warnings(false);

    for f in [
        "src/cmd/optiga_cmd.c",
        "src/common/optiga_lib_common.c",
        "src/common/optiga_lib_logger.c",
        "src/comms/optiga_comms_ifx_i2c.c",
        "src/comms/ifx_i2c/ifx_i2c.c",
        "src/comms/ifx_i2c/ifx_i2c_config.c",
        "src/comms/ifx_i2c/ifx_i2c_data_link_layer.c",
        "src/comms/ifx_i2c/ifx_i2c_physical_layer.c",
        // Empty without OPTIGA_COMMS_SHIELDED_CONNECTION.
        "src/comms/ifx_i2c/ifx_i2c_presentation_layer.c",
        "src/comms/ifx_i2c/ifx_i2c_transport_layer.c",
        "src/crypt/optiga_crypt.c",
        "src/util/optiga_util.c",
    ] {
        build.file(lib.join(f));
    }
    // Linux PAL: /dev/i2c-N + pthread timers. pal_gpio.c is linked but never
    // acts: the pin contexts in csrc/pal_config.c are NULL.
    for f in [
        "pal.c",
        "pal_gpio.c",
        "pal_i2c.c",
        "pal_logger.c",
        "pal_os_datastore.c",
        "pal_os_event.c",
        "pal_os_lock.c",
        "pal_os_memory.c",
        "pal_os_timer.c",
        "pal_shared_mutex.c",
    ] {
        build.file(lib.join("extras/pal/linux").join(f));
    }
    build.file("csrc/pal_config.c");
    build.compile("optiga_trust_m");

    // shm_open in pal_shared_mutex.c
    println!("cargo:rustc-link-lib=rt");
    println!("cargo:rustc-link-lib=pthread");
}
