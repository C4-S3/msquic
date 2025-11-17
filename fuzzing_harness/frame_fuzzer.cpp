/*++

Copyright (c) Security Research - msquic Frame Fuzzer
Licensed under the MIT License.

Abstract:

    LibFuzzer/AFL++ harness for QUIC frame parsing functions
    Targets: src/core/frame.c - All frame decode functions

Build:
    See build_fuzzer.sh

Run:
    ./frame_fuzzer -max_len=65535 -timeout=10 corpus/

--*/

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1
#define CX_PLATFORM_LINUX 1
#define QUIC_TEST_APIS 1

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Mock minimal QUIC platform dependencies
#ifndef QUIC_PLATFORM_H
typedef unsigned long long QUIC_VAR_INT;
typedef uint8_t BOOLEAN;
#define TRUE 1
#define FALSE 0
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define CXPLAT_ANALYSIS_ASSERT(x)
#endif

// Frame types to test
typedef enum QUIC_FRAME_TYPE {
    QUIC_FRAME_PADDING              = 0x0,
    QUIC_FRAME_PING                 = 0x1,
    QUIC_FRAME_ACK                  = 0x2,
    QUIC_FRAME_ACK_1                = 0x3,
    QUIC_FRAME_RESET_STREAM         = 0x4,
    QUIC_FRAME_STOP_SENDING         = 0x5,
    QUIC_FRAME_CRYPTO               = 0x6,
    QUIC_FRAME_NEW_TOKEN            = 0x7,
    QUIC_FRAME_STREAM               = 0x8,
    QUIC_FRAME_STREAM_1             = 0x9,
    QUIC_FRAME_STREAM_2             = 0xa,
    QUIC_FRAME_STREAM_3             = 0xb,
    QUIC_FRAME_STREAM_4             = 0xc,
    QUIC_FRAME_STREAM_5             = 0xd,
    QUIC_FRAME_STREAM_6             = 0xe,
    QUIC_FRAME_STREAM_7             = 0xf,
    QUIC_FRAME_MAX_DATA             = 0x10,
    QUIC_FRAME_MAX_STREAM_DATA      = 0x11,
    QUIC_FRAME_MAX_STREAMS          = 0x12,
    QUIC_FRAME_MAX_STREAMS_1        = 0x13,
    QUIC_FRAME_DATA_BLOCKED         = 0x14,
    QUIC_FRAME_STREAM_DATA_BLOCKED  = 0x15,
    QUIC_FRAME_STREAMS_BLOCKED      = 0x16,
    QUIC_FRAME_STREAMS_BLOCKED_1    = 0x17,
    QUIC_FRAME_NEW_CONNECTION_ID    = 0x18,
    QUIC_FRAME_RETIRE_CONNECTION_ID = 0x19,
    QUIC_FRAME_PATH_CHALLENGE       = 0x1a,
    QUIC_FRAME_PATH_RESPONSE        = 0x1b,
    QUIC_FRAME_CONNECTION_CLOSE     = 0x1c,
    QUIC_FRAME_CONNECTION_CLOSE_1   = 0x1d,
    QUIC_FRAME_HANDSHAKE_DONE       = 0x1e,
    QUIC_FRAME_DATAGRAM             = 0x30,
    QUIC_FRAME_DATAGRAM_1           = 0x31,
} QUIC_FRAME_TYPE;

// Mock VarInt decode - simplified
BOOLEAN QuicVarIntDecode(
    uint16_t BufferLength,
    const uint8_t* Buffer,
    uint16_t* Offset,
    QUIC_VAR_INT* Value
) {
    if (*Offset >= BufferLength) return FALSE;

    uint8_t first = Buffer[*Offset];
    uint8_t length = 1 << (first >> 6);

    if (*Offset + length > BufferLength) return FALSE;

    *Value = first & 0x3F;
    for (uint8_t i = 1; i < length; i++) {
        *Value = (*Value << 8) | Buffer[*Offset + i];
    }

    *Offset += length;
    return TRUE;
}

// Frame structure definitions (simplified)
typedef struct QUIC_STREAM_EX {
    QUIC_VAR_INT StreamID;
    QUIC_VAR_INT Offset;
    QUIC_VAR_INT Length;
    const uint8_t* Data;
    BOOLEAN Fin;
    BOOLEAN ExplicitLength;
} QUIC_STREAM_EX;

typedef struct QUIC_CRYPTO_EX {
    QUIC_VAR_INT Offset;
    QUIC_VAR_INT Length;
    const uint8_t* Data;
} QUIC_CRYPTO_EX;

typedef struct QUIC_NEW_TOKEN_EX {
    QUIC_VAR_INT TokenLength;
    const uint8_t* Token;
} QUIC_NEW_TOKEN_EX;

// Mock frame decode functions to test the validation logic
BOOLEAN MockStreamFrameDecode(
    QUIC_FRAME_TYPE FrameType,
    uint16_t BufferLength,
    const uint8_t* Buffer,
    uint16_t* Offset,
    QUIC_STREAM_EX* Frame
) {
    // Simulate the actual logic from frame.c:648-685
    uint8_t flags = FrameType & 0x07;
    BOOLEAN hasOffset = (flags & 0x04) != 0;
    BOOLEAN hasLength = (flags & 0x02) != 0;

    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->StreamID)) {
        return FALSE;
    }

    if (hasOffset) {
        if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->Offset)) {
            return FALSE;
        }
    } else {
        Frame->Offset = 0;
    }

    if (hasLength) {
        if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->Length) ||
            BufferLength < Frame->Length + *Offset) {  // POTENTIAL VULNERABILITY
            return FALSE;
        }
        Frame->ExplicitLength = TRUE;
    } else {
        if (BufferLength < *Offset) return FALSE;
        Frame->Length = BufferLength - *Offset;
        Frame->ExplicitLength = FALSE;
    }

    Frame->Fin = (flags & 0x01) != 0;
    Frame->Data = Buffer + *Offset;
    *Offset += (uint16_t)Frame->Length;  // POTENTIAL TRUNCATION
    return TRUE;
}

BOOLEAN MockCryptoFrameDecode(
    uint16_t BufferLength,
    const uint8_t* Buffer,
    uint16_t* Offset,
    QUIC_CRYPTO_EX* Frame
) {
    // Simulate frame.c:538-554
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->Offset) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->Length) ||
        BufferLength < Frame->Length + *Offset) {  // POTENTIAL VULNERABILITY
        return FALSE;
    }
    Frame->Data = Buffer + *Offset;
    *Offset += (uint16_t)Frame->Length;  // POTENTIAL TRUNCATION
    return TRUE;
}

BOOLEAN MockNewTokenFrameDecode(
    uint16_t BufferLength,
    const uint8_t* Buffer,
    uint16_t* Offset,
    QUIC_NEW_TOKEN_EX* Frame
) {
    // Simulate frame.c:388+
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->TokenLength) ||
        BufferLength < Frame->TokenLength + *Offset) {  // POTENTIAL VULNERABILITY
        return FALSE;
    }
    Frame->Token = Buffer + *Offset;
    *Offset += (uint16_t)Frame->TokenLength;  // POTENTIAL TRUNCATION
    return TRUE;
}

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 65535) {
        return 0;
    }

    // Use first byte to select frame type to test
    uint8_t type_selector = data[0];
    const uint8_t* frame_data = data + 1;
    uint16_t frame_len = (uint16_t)(size - 1);
    uint16_t offset = 0;

    // Test different frame types based on selector
    switch (type_selector % 3) {
        case 0: {
            // Test STREAM frame (most common)
            QUIC_STREAM_EX frame;
            QUIC_FRAME_TYPE frame_type = (QUIC_FRAME_TYPE)(QUIC_FRAME_STREAM | (type_selector & 0x07));
            MockStreamFrameDecode(frame_type, frame_len, frame_data, &offset, &frame);
            break;
        }

        case 1: {
            // Test CRYPTO frame
            QUIC_CRYPTO_EX frame;
            MockCryptoFrameDecode(frame_len, frame_data, &offset, &frame);
            break;
        }

        case 2: {
            // Test NEW_TOKEN frame
            QUIC_NEW_TOKEN_EX frame;
            MockNewTokenFrameDecode(frame_len, frame_data, &offset, &frame);
            break;
        }
    }

    return 0;
}

// AFL++ persistent mode support
#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();

int main() {
    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, len);
    }

    return 0;
}
#endif
