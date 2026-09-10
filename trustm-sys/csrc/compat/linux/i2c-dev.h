/*
 * Fallback for toolchains without Linux UAPI headers (e.g. a bare musl cross
 * compiler). Included via -idirafter, so a real <linux/i2c-dev.h> from the
 * sysroot takes precedence when present.
 *
 * These ioctl numbers are kernel ABI, identical on every architecture, and
 * have not changed since Linux 2.x. The Infineon Linux PAL only uses
 * I2C_SLAVE; the rest are listed for completeness.
 */
#ifndef _TMC_COMPAT_LINUX_I2C_DEV_H
#define _TMC_COMPAT_LINUX_I2C_DEV_H

#define I2C_RETRIES 0x0701     /* number of times a device address should be polled */
#define I2C_TIMEOUT 0x0702     /* set timeout in units of 10 ms */
#define I2C_SLAVE 0x0703       /* use this slave address */
#define I2C_SLAVE_FORCE 0x0706 /* ...even if it is already in use by a driver */
#define I2C_TENBIT 0x0704      /* 0 for 7 bit addrs, != 0 for 10 bit */
#define I2C_FUNCS 0x0705       /* get the adapter functionality mask */
#define I2C_RDWR 0x0707        /* combined R/W transfer (one STOP only) */
#define I2C_PEC 0x0708         /* != 0 to use PEC with SMBus */
#define I2C_SMBUS 0x0720       /* SMBus transfer */

#endif /* _TMC_COMPAT_LINUX_I2C_DEV_H */
