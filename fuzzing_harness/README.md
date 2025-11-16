# MSQUIC Frame Fuzzing Harness

This directory contains a targeted fuzzing harness for QUIC frame parsing functions, based on the security analysis findings.

## Overview

**Target:** QUIC frame decoding functions (src/core/frame.c)
**Objective:** Find integer overflow, buffer overflow, and parsing vulnerabilities
**Priority:** 🔴 CRITICAL (highest-value target identified in security analysis)

## Files

- `frame_fuzzer.cpp` - LibFuzzer/AFL++ harness targeting frame decode functions
- `generate_corpus.py` - Python script to generate seed corpus
- `build_fuzzer.sh` - Build script for compiling the fuzzer
- `README.md` - This file

## Quick Start

### 1. Generate Seed Corpus

```bash
python3 generate_corpus.py
```

This creates a `corpus/` directory with ~50 seed files covering:
- Valid QUIC frames (STREAM, CRYPTO, ACK, NEW_TOKEN, etc.)
- Edge cases (zero-length, maximum values)
- Attack patterns (integer overflow triggers)

### 2. Build the Fuzzer

**Option A: LibFuzzer (recommended for local testing)**
```bash
./build_fuzzer.sh libfuzzer
```

**Option B: AFL++ (recommended for extended campaigns)**
```bash
./build_fuzzer.sh afl
```

Requirements:
- clang with sanitizer support
- AFL++ (for AFL mode): `sudo apt install afl++`

### 3. Run Fuzzing

**LibFuzzer:**
```bash
./build/frame_fuzzer -max_len=65535 -timeout=10 corpus/
```

**AFL++:**
```bash
afl-fuzz -i corpus/ -o findings/ -- ./build/frame_fuzzer_afl
```

## What This Fuzzer Tests

### Targeted Functions

1. **QuicStreamFrameDecode** (frame.c:648)
   - Most common frame type
   - Complex length handling with flags
   - Integer overflow pattern: `BufferLength < Frame->Length + *Offset`

2. **QuicCryptoFrameDecode** (frame.c:538)
   - Handshake-critical
   - Same integer overflow pattern
   - Type truncation: `*Offset += (uint16_t)Frame->Length`

3. **QuicNewTokenFrameDecode** (frame.c:388)
   - Token buffer handling
   - Length validation vulnerabilities

### Vulnerability Patterns Being Tested

#### 🎯 Primary Target: Integer Overflow
```c
// Pattern found in multiple frame decode functions:
if (BufferLength < Frame->Length + *Offset) {  // POTENTIAL OVERFLOW
    return FALSE;
}
*Offset += (uint16_t)Frame->Length;  // TRUNCATION
```

**Concern:**
- `Frame->Length` is QUIC_VAR_INT (uint64_t, up to 2^62-1)
- `*Offset` is uint16_t (max 65535)
- Overflow in addition could bypass validation
- Truncation could cause out-of-bounds access

#### Secondary Targets
- VarInt decoding edge cases
- Buffer bounds checking
- Type confusion
- Off-by-one errors

## Expected Results

### Success Criteria
- **Coverage:** >90% of frame.c
- **Runtime:** 2-4 weeks for comprehensive testing
- **Crashes:** Likely to find memory safety issues

### Crash Triage

When the fuzzer finds a crash:

1. **Minimize the test case:**
   ```bash
   ./build/frame_fuzzer -minimize_crash=1 crash-file
   ```

2. **Reproduce under debugger:**
   ```bash
   gdb --args ./build/frame_fuzzer crash-file
   ```

3. **Analyze with ASan output:**
   The fuzzer is built with AddressSanitizer, which will provide:
   - Crash type (heap overflow, use-after-free, etc.)
   - Stack trace
   - Memory access details

4. **Determine exploitability:**
   - Can attacker control the overflow size?
   - Is the crash in a networked code path?
   - What are the prerequisites (handshake state, etc.)?

## Integration with OSS-Fuzz

To add this fuzzer to the existing OSS-Fuzz integration:

1. Copy `frame_fuzzer.cpp` to `src/fuzzing/`
2. Update `oss-fuzz/projects/msquic/build.sh`:
   ```bash
   # Add frame fuzzer build
   $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
       -I src/inc -I src/core \
       src/fuzzing/frame_fuzzer.cpp \
       -o $OUT/frame_fuzzer
   ```
3. Copy corpus files to OSS-Fuzz seed corpus
4. Submit PR to OSS-Fuzz repository

## Fuzzing Strategy

### Phase 1: Initial Discovery (Week 1)
- Run fuzzer with default settings
- Monitor for crashes
- Achieve baseline coverage

### Phase 2: Corpus Refinement (Week 2)
- Analyze coverage gaps
- Add seeds for uncovered code paths
- Implement custom mutator if needed

### Phase 3: Targeted Testing (Week 3-4)
- Focus on integer overflow scenarios
- Test maximum VarInt values
- Test boundary conditions

### Phase 4: Variant Analysis (Ongoing)
- Apply patterns to other frame types
- Test similar code in packet.c
- Extend to transport parameter fuzzing

## Custom Mutations (Advanced)

For QUIC-aware fuzzing, consider implementing a custom mutator:

```cpp
// Example: Mutate VarInt length fields
extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed
) {
    // Find VarInt encodings
    // Mutate to boundary values: 63, 64, 16383, 16384, etc.
    // Insert max values: 0x3FFFFFFFFFFFFFFF
    return NewSize;
}
```

## Known Limitations

1. **Simplified Implementation:**
   - This harness mocks some QUIC structures
   - May miss bugs in actual msquic integration code
   - Consider fuzzing the full library for complete coverage

2. **State Machine:**
   - Doesn't test connection state interactions
   - Doesn't test frame sequencing
   - Doesn't test handshake flows

3. **Cryptography:**
   - Tests decrypted frames only
   - Doesn't test packet decryption
   - Doesn't test key derivation

For comprehensive testing, combine with:
- Full protocol fuzzer (sends actual QUIC packets)
- State machine fuzzer
- Cryptographic fuzzer

## References

- Security Analysis Report: `../SECURITY_ANALYSIS_REPORT.md`
- QUIC RFC 9000: https://www.rfc-editor.org/rfc/rfc9000.html
- msquic Documentation: https://github.com/microsoft/msquic
- OSS-Fuzz Integration: `../src/fuzzing/README.md`

## Contact

For questions or results, contact the security research team or file an issue on the msquic GitHub repository.

---

**⚠️ IMPORTANT:** This is security research code. Do not use in production. Report any findings responsibly through proper disclosure channels.
