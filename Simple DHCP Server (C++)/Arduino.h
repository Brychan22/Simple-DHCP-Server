#pragma once
#include <Windows.h>
#include <sysinfoapi.h>
class Arduino
{
public:
    static unsigned int millis() {
        return (unsigned int)(GetTickCount64() % 0xFFFFFFFF);
    }
};

