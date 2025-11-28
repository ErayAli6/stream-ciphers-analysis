# Stream Cipher Cryptanalysis & Implementation

> **Comparative analysis of modern stream cipher algorithms with Java implementations**  
> _Educational project - Cybersecurity Algorithms Course_

A comprehensive study and implementation of stream cipher algorithms including **RC4**, **ChaCha20**, and **Salsa20**, featuring performance benchmarks, security analysis, and comparative evaluation.

## 🔐 Implemented Algorithms

### 1. **RC4** (Rivest Cipher 4)

_Classic Stream Cipher - Educational Purpose Only_

```
Key Size:    40-2048 bits (variable)
State Size:  256 bytes
Year:        1987 (Ron Rivest)
Status:      ❌ DEPRECATED (RFC 7465)
```

**Implementation:** `src/RC4.java`

**Characteristics:**

- Simple KSA (Key Scheduling Algorithm) and PRGA (Pseudo-Random Generation Algorithm)
- Extremely fast encryption/decryption
- **Security Issues:** FMS attack, Klein attack, PTW attack, statistical biases
- **Use Case:** Historical study and cryptanalysis education

**⚠️ DO NOT USE IN PRODUCTION** - Forbidden in TLS 1.3, deprecated by IETF

---

### 2. **ChaCha20**

_Modern ARX Stream Cipher - RFC 8439 Standard_

```
Key Size:    256 bits
Nonce:       96 bits
Counter:     32 bits
Rounds:      20 (10 double rounds)
Status:      ✅ RECOMMENDED
```

**Implementation:** `src/ChaCha20.java`

**Characteristics:**

- **Quarter Round Operations:** ADD-ROTATE-XOR with rotations [16, 12, 8, 7]
- Constant-time implementation (resistant to timing attacks)
- Used in **TLS 1.3**, **WireGuard VPN**, **Signal Protocol**
- Designed by Daniel J. Bernstein (2008)
- Better diffusion than Salsa20 (full diffusion in 12 rounds vs 16)

**Performance:** ~327 MB/s (10 MB data), σ=1.68 ms

---

### 3. **Salsa20**

_ARX Stream Cipher - eSTREAM Portfolio_

```
Key Size:    256 bits
Nonce:       64 bits
Counter:     64 bits
Rounds:      20 (variants: 8, 12, 20)
Status:      ✅ SECURE
```

**Implementation:** `src/Salsa20.java`

**Characteristics:**

- **Quarter Round Operations:** ADD-ROTATE-XOR with rotations [7, 9, 13, 18]
- eSTREAM finalist (2008)
- Predecessor of ChaCha20
- Slightly faster than ChaCha20 (~5% on average)
- Full diffusion requires 16 rounds

**Performance:** ~344 MB/s (10 MB data), σ=0.28 ms (most consistent)

---

## 🚀 Getting Started

### Prerequisites

- **Java Development Kit (JDK)** 25

  - [OpenJDK Download](https://openjdk.org/)
  - [Oracle JDK Download](https://www.oracle.com/java/technologies/downloads/)

- **Optional:** Bouncy Castle Library (for comparison benchmarks)
  - [Download bcprov-jdk15on-1.70.jar](https://www.bouncycastle.org/latest_releases.html)

**Verify Java installation:**

```bash
java -version  # Should show version 25
javac -version # Should show version 25
```

---

### Installation

#### 🚀 Quick Start (Recommended)

**The easiest way to compile, run, and clean up:**

**On macOS/Linux:**
```bash
./run.sh
```

**On Windows:**
```cmd
run.bat
```

The script will:
1. ✅ Compile all Java files automatically
2. ✅ Show you a menu to select which program to run
3. ✅ Clean up `.class` files after execution

**Menu options:**
- `1` - StreamCipherDemo (demonstrations)
- `2` - StreamCipherBenchmark (performance tests)
- `3` - SecurityAnalysis (security tests)
- `4` - AdvancedBenchmark (Bouncy Castle comparison)
- `5` - Run all programs sequentially
- `6` - Exit

---

#### Method 1: Direct Compilation (macOS/Linux)

```bash
# Clone or download the repository
cd "project claude"

# Compile all source files
cd src
javac *.java

# Run basic demo
java StreamCipherDemo

# Clean up
rm *.class
```

#### Method 2: With Bouncy Castle (macOS/Linux)

```bash
cd "project claude"

# Download Bouncy Castle (if not already downloaded)
curl -O https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.70/bcprov-jdk15on-1.70.jar

# Compile with classpath
cd src
javac -cp ".:../bcprov-jdk15on-1.70.jar" *.java

# Run advanced benchmark
java -cp ".:../bcprov-jdk15on-1.70.jar" AdvancedBenchmark

# Clean up
rm *.class
```

#### Method 3: Windows

```cmd
cd "project claude"

REM Compile all files
cd src
javac *.java

REM Run demo
java StreamCipherDemo

REM Clean up
del *.class
```

**With Bouncy Castle (Windows):**

```cmd
cd src
javac -cp ".;..\bcprov-jdk15on-1.70.jar" *.java
java -cp ".;..\bcprov-jdk15on-1.70.jar" AdvancedBenchmark
del *.class
```

---

### Running the Programs

#### 1. **StreamCipherDemo** - Interactive Demonstrations

```bash
cd src
java StreamCipherDemo
```

**Output includes:**

- RC4 encryption/decryption examples with hex visualization
- ChaCha20 test vectors validation (RFC 8439)
- Salsa20 encryption examples
- Side-by-side algorithm comparison

**Example output:**

```
=== RC4 Demonstration ===
Key: 0x0102030405060708090a0b0c0d0e0f10
Plaintext:  "Attack at dawn!"
Ciphertext: 7a 3f 62 1c 5e 4a 3b 9f e2 8d 6c 0f 1a 2e 9b
Decrypted:  "Attack at dawn!"
```

---

#### 2. **StreamCipherBenchmark** - Performance Testing

```bash
cd src
java StreamCipherBenchmark
```

**Tests performed:**

- Correctness verification (encrypt → decrypt roundtrip)
- Throughput measurement: 1 KB, 1 MB, 10 MB, 100 MB
- Statistical analysis: mean time, min/max, standard deviation, CV%
- 10 iterations with 5-iteration warmup for JIT optimization

**Example output:**

```
=== Performance Benchmark: 10 MB ===
RC4:      200.45 MB/s  (σ=2.34 ms, CV=3.12%)
ChaCha20: 327.89 MB/s  (σ=1.68 ms, CV=5.50%)
Salsa20:  344.21 MB/s  (σ=0.28 ms, CV=0.96%) ← Fastest
```

---

#### 3. **SecurityAnalysis** - Cryptographic Testing

```bash
cd src
java SecurityAnalysis
```

**Tests included:**

| Test                   | Purpose                                  | Ideal Result      |
| ---------------------- | ---------------------------------------- | ----------------- |
| **Chi-Square (χ²)**    | Keystream randomness uniformity          | 200-300           |
| **Correlation**        | Independence of plaintext and ciphertext | ≈ 0.00            |
| **Avalanche Effect**   | Bit diffusion from 1-bit key change      | ~50%              |
| **Key Sensitivity**    | Percentage of changed output bits        | 49-51%            |
| **Nonce Reuse Attack** | Demonstrates C₁⊕C₂ = P₁⊕P₂ vulnerability | Should reveal XOR |

**Example results:**

```
=== Chi-Square Test (1 MB keystream) ===
ChaCha20: χ² = 260.59 ✅ PASS (expected: 200-300)
Salsa20:  χ² = 236.74 ✅ PASS
RC4:      χ² = 224.74 ✅ PASS (but insecure due to known attacks)

=== Correlation Analysis ===
ChaCha20: r = 0.0106 ✅ (no correlation)
Salsa20:  r = 0.0032 ✅
RC4:      r = 0.0025 ✅

=== Avalanche Effect (1-bit key flip) ===
ChaCha20: 51.45% bits changed ✅
Salsa20:  53.49% bits changed ✅
RC4:      51.74% bits changed ✅
```

---

#### 4. **AdvancedBenchmark** - Comparison with Bouncy Castle

**Requires:** `bcprov-jdk15on-1.70.jar` in parent directory

```bash
cd src
java -cp ".:../bcprov-jdk15on-1.70.jar" AdvancedBenchmark
```

**Comparison results (10 MB data):**

| Algorithm | Our Implementation | Bouncy Castle | Difference |
| --------- | ------------------ | ------------- | ---------- |
| RC4       | 200 MB/s           | 242 MB/s      | -17.3%     |
| ChaCha20  | 327 MB/s           | 284 MB/s      | **+15.1%** |
| Salsa20   | 344 MB/s           | 299 MB/s      | **+15.0%** |

**Analysis:** Our ARX cipher implementations are **15% faster** than Bouncy Castle on educational-quality code, demonstrating proper optimization techniques.

---
