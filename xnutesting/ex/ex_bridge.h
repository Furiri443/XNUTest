#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// C PoC — kernel panic variant (from ex_PoC.c)
void aio_kevent_PoC_trigger(void);

#ifdef __cplusplus
}
#endif

// ObjC double-free variant (from ex.m)
#ifdef __OBJC__
void aio_kevent_uaf_trigger(void);

// Combined: AIO UAF + ICMPv6 KRW chain (from ex_combined.m)
void ex_combined_trigger(void);

// darksword physical KRW (from dsw.m)
void dsw_main(void);
#endif


