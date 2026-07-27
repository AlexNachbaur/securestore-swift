/*
 * Umbrella header for the CSecret system-library target.
 *
 * libsecret's own headers refuse to be included individually — <libsecret/secret.h> is the
 * only supported entry point — so this shim exists purely to give the module map a single
 * header to name.
 */

#ifndef SECURESTORE_CSECRET_SHIM_H
#define SECURESTORE_CSECRET_SHIM_H

#include <libsecret/secret.h>

#endif /* SECURESTORE_CSECRET_SHIM_H */
