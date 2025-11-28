import java.util.*;
import java.security.SecureRandom;

/**
 * АНАЛИЗ НА КРИПТОГРАФСКАТА СИГУРНОСТ
 * 
 * Тази програма извършва практически тестове за сигурност на поточните шифри:
 * 1. Randomness Testing - Chi-square тест за randomness
 * 2. Avalanche Effect - промяна в 1 бит води до 50% промяна в output
 * 3. Correlation Analysis - корелация между plaintext и ciphertext
 * 4. Key Sensitivity - различни ключове дават различни outputs
 * 5. Nonce Reuse Detection - опасности от повторно използване
 */
public class SecurityAnalysis {

    // ═══════════════════════════════════════════════════════════
    // 1. CHI-SQUARE ТЕСТ ЗА RANDOMNESS
    // ═══════════════════════════════════════════════════════════

    /**
     * Chi-square тест проверява дали keystream изглежда random.
     * Добър keystream трябва да има равномерно разпределение на байтове.
     * 
     * Chi-square = Σ((observed - expected)² / expected)
     * За 256 възможни байта, expected = length / 256
     * 
     * Добри стойности: 200-300 (колкото по-близо до 255, толкова по-random)
     */
    public static double chiSquareTest(byte[] data) {
        int[] frequency = new int[256];

        // Броене на честотата на всеки байт
        for (byte b : data) {
            frequency[b & 0xFF]++;
        }

        double expected = data.length / 256.0;
        double chiSquare = 0.0;

        for (int count : frequency) {
            double diff = count - expected;
            chiSquare += (diff * diff) / expected;
        }

        return chiSquare;
    }

    /**
     * Оценка на Chi-square резултата
     */
    public static String evaluateChiSquare(double chiSquare) {
        // За 255 degrees of freedom и α=0.05:
        // Critical value ≈ 293.25
        // Добър range: 200-300

        if (chiSquare < 200) {
            return "⚠️  ПОДОЗРИТЕЛНО (твърде uniform, може да има bias)";
        } else if (chiSquare <= 300) {
            return "✅ ОТЛИЧНО (статистически random)";
        } else if (chiSquare <= 350) {
            return "✅ ДОБРО (приемливо random)";
        } else {
            return "❌ ЛОШО (не е достатъчно random)";
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 2. AVALANCHE EFFECT ТЕСТ
    // ═══════════════════════════════════════════════════════════

    /**
     * Avalanche effect: промяна в 1 бит от КЛЮЧА трябва да промени
     * приблизително 50% от битовете в output keystream/ciphertext.
     * 
     * Това е критично свойство за сигурност - предотвратява related-key атаки.
     */
    public static double avalancheEffect(String algorithm, byte[] key1, byte[] key2, byte[] nonce,
            byte[] plaintext) {
        byte[] cipher1, cipher2;

        if (algorithm.equals("RC4")) {
            RC4 rc4_1 = new RC4(key1);
            RC4 rc4_2 = new RC4(key2);
            cipher1 = rc4_1.encrypt(new String(plaintext));
            cipher2 = rc4_2.encrypt(new String(plaintext));
        } else if (algorithm.equals("ChaCha20")) {
            ChaCha20 chacha1 = new ChaCha20(key1, nonce);
            ChaCha20 chacha2 = new ChaCha20(key2, nonce);
            cipher1 = chacha1.encrypt(new String(plaintext));
            cipher2 = chacha2.encrypt(new String(plaintext));
        } else { // Salsa20
            Salsa20 salsa1 = new Salsa20(key1, nonce);
            Salsa20 salsa2 = new Salsa20(key2, nonce);
            cipher1 = salsa1.encrypt(new String(plaintext));
            cipher2 = salsa2.encrypt(new String(plaintext));
        }

        // Брой различни битове
        int differentBits = 0;
        int totalBits = cipher1.length * 8;

        for (int i = 0; i < cipher1.length; i++) {
            int xor = (cipher1[i] ^ cipher2[i]) & 0xFF;
            differentBits += Integer.bitCount(xor);
        }

        return (double) differentBits / totalBits * 100.0;
    }

    // ═══════════════════════════════════════════════════════════
    // 3. КОРЕЛАЦИОНЕН АНАЛИЗ
    // ═══════════════════════════════════════════════════════════

    /**
     * Correlation между plaintext и ciphertext.
     * Добър шифър: correlation ≈ 0 (никаква връзка)
     */
    public static double correlationAnalysis(byte[] plaintext, byte[] ciphertext) {
        double sumX = 0, sumY = 0, sumXY = 0;
        double sumX2 = 0, sumY2 = 0;
        int n = plaintext.length;

        for (int i = 0; i < n; i++) {
            int x = plaintext[i] & 0xFF;
            int y = ciphertext[i] & 0xFF;

            sumX += x;
            sumY += y;
            sumXY += x * y;
            sumX2 += x * x;
            sumY2 += y * y;
        }

        double numerator = n * sumXY - sumX * sumY;
        double denominator = Math.sqrt((n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY));

        return Math.abs(numerator / denominator);
    }

    // ═══════════════════════════════════════════════════════════
    // 4. KEY SENSITIVITY ТЕСТ
    // ═══════════════════════════════════════════════════════════

    /**
     * Тест дали малка промяна в ключа води до напълно различен output.
     * Два ключа, различаващи се в 1 бит, трябва да дадат ~50% различни битове.
     */
    public static double keySensitivity(String algorithm, byte[] key1, byte[] key2,
            byte[] nonce, byte[] plaintext) {
        byte[] cipher1, cipher2;

        if (algorithm.equals("RC4")) {
            RC4 rc4_1 = new RC4(key1);
            RC4 rc4_2 = new RC4(key2);
            cipher1 = rc4_1.encrypt(new String(plaintext));
            cipher2 = rc4_2.encrypt(new String(plaintext));
        } else if (algorithm.equals("ChaCha20")) {
            ChaCha20 chacha1 = new ChaCha20(key1, nonce);
            ChaCha20 chacha2 = new ChaCha20(key2, nonce);
            cipher1 = chacha1.encrypt(new String(plaintext));
            cipher2 = chacha2.encrypt(new String(plaintext));
        } else { // Salsa20
            Salsa20 salsa1 = new Salsa20(key1, nonce);
            Salsa20 salsa2 = new Salsa20(key2, nonce);
            cipher1 = salsa1.encrypt(new String(plaintext));
            cipher2 = salsa2.encrypt(new String(plaintext));
        }

        int differentBits = 0;
        int totalBits = cipher1.length * 8;

        for (int i = 0; i < cipher1.length; i++) {
            int xor = (cipher1[i] ^ cipher2[i]) & 0xFF;
            differentBits += Integer.bitCount(xor);
        }

        return (double) differentBits / totalBits * 100.0;
    }

    // ═══════════════════════════════════════════════════════════
    // 5. NONCE REUSE ОПАСНОСТ
    // ═══════════════════════════════════════════════════════════

    /**
     * Демонстрация защо НИКОГА не трябва да преизползвате nonce.
     * Два различни текста с същия ключ и nonce позволяват XOR атака.
     */
    public static void nonceReuseAttack(String algorithm) {
        byte[] key = new byte[32]; // 32 bytes
        for (int i = 0; i < 32; i++)
            key[i] = (byte) i;
        byte[] nonce = algorithm.equals("Salsa20") ? new byte[8] : new byte[12]; // Еднакъв nonce!

        String message1 = "Attack at dawn";
        String message2 = "Attack at dusk";

        byte[] cipher1, cipher2;

        if (algorithm.equals("ChaCha20")) {
            ChaCha20 chacha1 = new ChaCha20(key, nonce);
            ChaCha20 chacha2 = new ChaCha20(key, nonce);
            cipher1 = chacha1.encrypt(message1);
            cipher2 = chacha2.encrypt(message2);
        } else { // Salsa20
            Salsa20 salsa1 = new Salsa20(key, nonce);
            Salsa20 salsa2 = new Salsa20(key, nonce);
            cipher1 = salsa1.encrypt(message1);
            cipher2 = salsa2.encrypt(message2);
        }

        System.out.println("\n❌ ОПАСНОСТ: Nonce Reuse Attack");
        System.out.println("═══════════════════════════════════════");
        System.out.println("Съобщение 1: " + message1);
        System.out.println("Съобщение 2: " + message2);
        System.out.println();
        System.out.println("Ciphertext 1: " + bytesToHex(cipher1, 20));
        System.out.println("Ciphertext 2: " + bytesToHex(cipher2, 20));
        System.out.println();

        // XOR на двата ciphertext-а
        byte[] xorResult = new byte[Math.min(cipher1.length, cipher2.length)];
        for (int i = 0; i < xorResult.length; i++) {
            xorResult[i] = (byte) (cipher1[i] ^ cipher2[i]);
        }

        System.out.println("C1 ⊕ C2:      " + bytesToHex(xorResult, 20));

        // Това е еквивалентно на P1 ⊕ P2 (keystream се елиминира!)
        byte[] plaintextXor = new byte[Math.min(message1.length(), message2.length())];
        for (int i = 0; i < plaintextXor.length; i++) {
            plaintextXor[i] = (byte) (message1.getBytes()[i] ^ message2.getBytes()[i]);
        }

        System.out.println("P1 ⊕ P2:      " + bytesToHex(plaintextXor, 20));
        System.out.println();
        System.out.println("⚠️  C1 ⊕ C2 = P1 ⊕ P2 (keystream се елиминира!)");
        System.out.println("⚠️  Атакуващ може да извлече информация за plaintexts!");
    }

    // ═══════════════════════════════════════════════════════════
    // ПОМОЩНИ ФУНКЦИИ
    // ═══════════════════════════════════════════════════════════

    private static String bytesToHex(byte[] bytes, int maxLen) {
        StringBuilder sb = new StringBuilder();
        int len = Math.min(bytes.length, maxLen);
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        if (bytes.length > maxLen) {
            sb.append("...");
        }
        return sb.toString();
    }

    private static byte[] flipOneBit(byte[] data, int position) {
        byte[] result = data.clone();
        int byteIndex = position / 8;
        int bitIndex = position % 8;
        result[byteIndex] ^= (1 << bitIndex);
        return result;
    }

    // ═══════════════════════════════════════════════════════════
    // ГЛАВНА ПРОГРАМА
    // ═══════════════════════════════════════════════════════════

    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║   АНАЛИЗ НА КРИПТОГРАФСКАТА СИГУРНОСТ                      ║");
        System.out.println("║   Практически тестове на поточни шифри                     ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝");
        System.out.println();

        // Подготовка на тестови данни
        byte[] key = new byte[32];
        byte[] nonce12 = new byte[12]; // За ChaCha20
        byte[] nonce8 = new byte[8]; // За Salsa20
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(nonce12);
        new SecureRandom().nextBytes(nonce8);

        byte[] plaintext = new byte[10000]; // 10 KB данни
        new SecureRandom().nextBytes(plaintext);

        String[] algorithms = { "RC4", "ChaCha20", "Salsa20" };

        // ═══════════════════════════════════════════════════════════
        // ТЕСТ 1: RANDOMNESS (Chi-Square)
        // ═══════════════════════════════════════════════════════════

        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║   ТЕСТ 1: RANDOMNESS НА KEYSTREAM (Chi-Square)             ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("Тестване дали keystream изглежда random (равномерно разпределение)");
        System.out.println("Добри стойности: 200-300 (колкото по-близо до 255, толкова по-добре)");
        System.out.println();

        for (String algo : algorithms) {
            byte[] ciphertext;

            if (algo.equals("RC4")) {
                RC4 rc4 = new RC4(key);
                ciphertext = rc4.encrypt(new String(plaintext));
            } else if (algo.equals("ChaCha20")) {
                ChaCha20 chacha = new ChaCha20(key, nonce12);
                ciphertext = chacha.encrypt(new String(plaintext));
            } else {
                Salsa20 salsa = new Salsa20(key, nonce8);
                ciphertext = salsa.encrypt(new String(plaintext));
            }

            double chiSquare = chiSquareTest(ciphertext);
            String evaluation = evaluateChiSquare(chiSquare);

            System.out.printf("%-10s | Chi-Square: %7.2f | %s%n",
                    algo, chiSquare, evaluation);
        }

        System.out.println();

        // ═══════════════════════════════════════════════════════════
        // ТЕСТ 2: AVALANCHE EFFECT
        // ═══════════════════════════════════════════════════════════

        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║   ТЕСТ 2: AVALANCHE EFFECT                                 ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("Промяна в 1 бит от КЛЮЧА → ~50% промяна в output");
        System.out.println("Добри стойности: 45-55% (колкото по-близо до 50%, толкова по-добре)");
        System.out.println();

        byte[] testPlaintext = "The quick brown fox jumps over the lazy dog".getBytes();
        byte[] modifiedKey = flipOneBit(key.clone(), 0); // Flip първия бит на ключа

        for (String algo : algorithms) {
            byte[] nonceToUse = algo.equals("Salsa20") ? nonce8 : nonce12;
            double avalanche = avalancheEffect(algo, key, modifiedKey, nonceToUse, testPlaintext);
            String evaluation = (avalanche >= 45 && avalanche <= 55) ? "✅ ОТЛИЧНО"
                    : (avalanche >= 40 && avalanche <= 60) ? "✅ ДОБРО" : "⚠️  СЛАБО";

            System.out.printf("%-10s | Променени битове: %5.2f%% | %s%n",
                    algo, avalanche, evaluation);
        }

        System.out.println();

        // ═══════════════════════════════════════════════════════════
        // ТЕСТ 3: КОРЕЛАЦИЯ PLAINTEXT-CIPHERTEXT
        // ═══════════════════════════════════════════════════════════

        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║   ТЕСТ 3: КОРЕЛАЦИЯ PLAINTEXT ↔ CIPHERTEXT                 ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("Корелация между входни и изходни данни");
        System.out.println("Добри стойности: близо до 0 (няма корелация)");
        System.out.println();

        for (String algo : algorithms) {
            byte[] ciphertext;

            if (algo.equals("RC4")) {
                RC4 rc4 = new RC4(key);
                ciphertext = rc4.encrypt(new String(testPlaintext));
            } else if (algo.equals("ChaCha20")) {
                ChaCha20 chacha = new ChaCha20(key, nonce12);
                ciphertext = chacha.encrypt(new String(testPlaintext));
            } else {
                Salsa20 salsa = new Salsa20(key, nonce8);
                ciphertext = salsa.encrypt(new String(testPlaintext));
            }

            double correlation = correlationAnalysis(testPlaintext, ciphertext);
            String evaluation = (correlation < 0.1) ? "✅ ОТЛИЧНО" : (correlation < 0.2) ? "✅ ДОБРО" : "⚠️  СЛАБО";

            System.out.printf("%-10s | Корелация: %6.4f | %s%n",
                    algo, correlation, evaluation);
        }

        System.out.println();

        // ═══════════════════════════════════════════════════════════
        // ТЕСТ 4: KEY SENSITIVITY
        // ═══════════════════════════════════════════════════════════

        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║   ТЕСТ 4: KEY SENSITIVITY                                  ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("Два ключа, различаващи се в 1 бит → ~50% различни битове в output");
        System.out.println("Добри стойности: 45-55%");
        System.out.println();

        byte[] key2 = flipOneBit(key, 0);

        for (String algo : algorithms) {
            byte[] nonceToUse = algo.equals("Salsa20") ? nonce8 : nonce12;
            double sensitivity = keySensitivity(algo, key, key2, nonceToUse, testPlaintext);
            String evaluation = (sensitivity >= 45 && sensitivity <= 55) ? "✅ ОТЛИЧНО"
                    : (sensitivity >= 40 && sensitivity <= 60) ? "✅ ДОБРО" : "⚠️  СЛАБО";

            System.out.printf("%-10s | Променени битове: %5.2f%% | %s%n",
                    algo, sensitivity, evaluation);
        }

        System.out.println();

        // ═══════════════════════════════════════════════════════════
        // ТЕСТ 5: NONCE REUSE АТАКА
        // ═══════════════════════════════════════════════════════════

        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║   ТЕСТ 5: NONCE REUSE ATTACK DEMONSTRATION                 ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝");

        nonceReuseAttack("ChaCha20");

        // ═══════════════════════════════════════════════════════════
        // ОБОБЩЕНИЕ
        // ═══════════════════════════════════════════════════════════

        System.out.println();
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║   ОБОБЩЕНИЕ НА СИГУРНОСТТА                                 ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("🔍 АНАЛИЗ:");
        System.out.println();
        System.out.println("1. RANDOMNESS:");
        System.out.println("   • RC4 има известен bias в първите байтове (FMS атака)");
        System.out.println("   • ChaCha20 и Salsa20 имат отлична randomness");
        System.out.println();
        System.out.println("2. AVALANCHE EFFECT:");
        System.out.println("   • Малка промяна в ключа → голяма промяна в output");
        System.out.println("   • ChaCha20/Salsa20 постигат близо 50% (отличен avalanche effect)");
        System.out.println("   • RC4 също показва добра дифузия");
        System.out.println();
        System.out.println("3. КОРЕЛАЦИЯ:");
        System.out.println("   • Всички алгоритми имат ниска корелация (добро)");
        System.out.println("   • Plaintext не се вижда в ciphertext");
        System.out.println();
        System.out.println("4. KEY SENSITIVITY:");
        System.out.println("   • Малка промяна в ключа → голяма промяна в output");
        System.out.println("   • Защитава от related-key атаки");
        System.out.println();
        System.out.println("5. NONCE REUSE:");
        System.out.println("   ❌ НИКОГА не преизползвайте nonce със същия ключ!");
        System.out.println("   • Води до пълен компромис на сигурността");
        System.out.println("   • XOR на ciphertexts дава XOR на plaintexts");
        System.out.println();
        System.out.println("🎯 ПРЕПОРЪКИ:");
        System.out.println("   ✅ ChaCha20 - Най-сигурен, без известни уязвимости");
        System.out.println("   ✅ Salsa20  - Сигурен, доказана конструкция");
        System.out.println("   ❌ RC4      - НЕСИГУРЕН, има множество атаки");
        System.out.println();
        System.out.println("════════════════════════════════════════════════════════════");
    }
}
