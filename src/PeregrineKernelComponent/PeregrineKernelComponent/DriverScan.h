#pragma once
#include <fltKernel.h>

// Enumerate loaded kernel drivers and report each to userland.
// Blacklisted drivers are flagged in the JSON output.
NTSTATUS DriverScanEnumerate(void);
