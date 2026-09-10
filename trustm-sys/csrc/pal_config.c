/*
 * Platform wiring for the Linux PAL: I2C bus, slave address, GPIOs.
 * Replaces extras/pal/linux/target/rpi3/pal_ifx_i2c_config.c.
 *
 * GPIO contexts are NULL: the library then skips pin handling and relies on
 * the I2C soft reset selected in trustm_sys_config.h. That keeps the build
 * free of sysfs GPIO and libgpiod. Bus and address are set at runtime with
 * trustm_sys_configure() before the first open.
 */
#include <stdint.h>

#include "ifx_i2c_config.h"
#include "pal_gpio.h"
#include "pal_i2c.h"
#include "pal_linux.h"

static pal_linux_t linux_i2c = {"/dev/i2c-1", 0, NULL};

pal_i2c_t optiga_pal_i2c_context_0 = {
    (void *)&linux_i2c, /* platform context */
    NULL,               /* upper layer context */
    NULL,               /* upper layer event handler */
    0x30,               /* Trust M default I2C slave address */
};

pal_gpio_t optiga_vdd_0 = {NULL};
pal_gpio_t optiga_reset_0 = {NULL};

/* `dev` must stay valid for the life of the process. `addr` is the 7-bit
 * slave address; 0 keeps the current one. */
void trustm_sys_configure(const char *dev, uint8_t addr) {
    if (dev != NULL && dev[0] != '\0') {
        linux_i2c.i2c_if = dev;
    }
    if (addr != 0) {
        optiga_pal_i2c_context_0.slave_address = addr;
    }
}
