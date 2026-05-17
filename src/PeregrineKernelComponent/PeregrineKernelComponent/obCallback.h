#pragma once
#include <fltKernel.h>

#ifndef CALLBACK_H
#define CALLBACK_H

extern PVOID callbackRegistrationHandle;

NTSTATUS createRegistration(void);
VOID unregisterRegistration(void);

#endif
