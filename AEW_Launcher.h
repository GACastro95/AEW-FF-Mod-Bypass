#pragma once

#ifdef MODLOADER_EXPORTS
#define MODLOADER_API __declspec(dllexport)
#else
#define MODLOADER_API __declspec(dllimport)
#endif

extern "C" MODLOADER_API int RunLauncher();