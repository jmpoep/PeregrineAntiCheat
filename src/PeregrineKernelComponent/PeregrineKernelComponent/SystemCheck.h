#pragma once
#include <fltKernel.h>

// Run all system integrity checks (test-signing, HVCI, CPU/hypervisor)
// and report results to userland via ComsSendToUser.
NTSTATUS SystemCheckRunAll(void);
