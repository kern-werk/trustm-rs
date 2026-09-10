/* Header set fed to bindgen. Regenerate src/bindings.rs with `just bindgen`. */
#include "optiga_lib_config.h"
#include "optiga_lib_types.h"
#include "optiga_lib_common.h"
#include "optiga_lib_return_codes.h"
#include "optiga_util.h"
#include "optiga_crypt.h"
#include "ifx_i2c_config.h"
#include "optiga_comms.h"
#include "pal.h"
#include "pal_i2c.h"
#include "pal_gpio.h"
#include "pal_os_timer.h"
#include "pal_os_event.h"
#include "pal_linux.h"

void trustm_sys_configure(const char *dev, uint8_t addr);
