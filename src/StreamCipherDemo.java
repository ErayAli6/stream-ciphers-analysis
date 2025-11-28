/**
 * Stream Cipher Demo - Демонстрационна програма
 * 
 * Интерактивна демонстрация на всички имплементирани поточни шифри
 * с практически примери за използване.
 * 
 * @author Курсова работа по АSК
 * @version 1.0
 */
public class StreamCipherDemo {

    /**
     * Конвертира байтов масив в hex string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Демонстрация на RC4
     */
    private static void demoRC4() {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║                    RC4 ДЕМОНСТРАЦИЯ                        ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        System.out.println("⚠️  ВНИМАНИЕ: RC4 е остарял и НЕ ТРЯБВА да се използва!");
        System.out.println("   Тази демонстрация е само за образователни цели.\n");

        // Пример 1: Основно криптиране
        System.out.println("─────────────────────────────────────────────────────────────");
        System.out.println("Пример 1: Основно криптиране с RC4");
        System.out.println("─────────────────────────────────────────────────────────────\n");

        String key = "MySecretKey";
        String plaintext = "Конфиденциално съобщение";

        System.out.println("Ключ:      " + key);
        System.out.println("Plaintext: " + plaintext + "\n");

        RC4 cipher = new RC4(key.getBytes());
        byte[] encrypted = cipher.encrypt(plaintext);

        System.out.println("Encrypted (Hex): " + bytesToHex(encrypted) + "\n");

        cipher.reset(key.getBytes());
        String decrypted = cipher.decrypt(encrypted);

        System.out.println("Decrypted: " + decrypted);
        System.out.println("Верификация: " + (plaintext.equals(decrypted) ? "✓" : "✗") + "\n");

        // Пример 2: Различни дължини на ключове
        System.out.println("─────────────────────────────────────────────────────────────");
        System.out.println("Пример 2: Влияние на дължината на ключа");
        System.out.println("─────────────────────────────────────────────────────────────\n");

        String testMessage = "Test";
        String[] keys = { "Key", "LongerKey123", "VeryLongSecretKeyFor256BitSecurity!!" };

        for (String k : keys) {
            RC4 c = new RC4(k.getBytes());
            byte[] enc = c.encrypt(testMessage);
            System.out.printf("Ключ (%3d бита): %-40s → %s%n",
                    k.length() * 8, k, bytesToHex(enc));
        }
        System.out.println();

        // Пример 3: Демонстрация на уязвимост при повторно използване на ключ
        System.out.println("─────────────────────────────────────────────────────────────");
        System.out.println("Пример 3: Опасност от повторно използване на ключ (без IV)");
        System.out.println("─────────────────────────────────────────────────────────────\n");

        String commonKey = "SharedKey";
        String msg1 = "Първо съобщение";
        String msg2 = "Второ съобщение";

        RC4 cipher1 = new RC4(commonKey.getBytes());
        byte[] enc1 = cipher1.encrypt(msg1);

        RC4 cipher2 = new RC4(commonKey.getBytes());
        byte[] enc2 = cipher2.encrypt(msg2);

        System.out.println("❌ ПРОБЛЕМ: Използване на един и същ ключ без nonce!");
        System.out.println("   Съобщение 1: " + bytesToHex(enc1));
        System.out.println("   Съобщение 2: " + bytesToHex(enc2));
        System.out.println("   → Първите байтове генерират идентичен keystream!");
        System.out.println("   → Атакуващ може да извлече информация чрез XOR на шифротекстовете!\n");

        System.out.println("═══════════════════════════════════════════════════════════\n");
    }

    /**
     * Демонстрация на ChaCha20
     */
    private static void demoChaCha20() {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║                 CHACHA20 ДЕМОНСТРАЦИЯ                      ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        System.out.println("✅ ChaCha20 е съвременен и сигурен шифър (RFC 8439)\n");

        // Пример 1: Правилно използване
        System.out.println("─────────────────────────────────────────────────────────────");
        System.out.println("Пример 1: Правилно използване на ChaCha20");
        System.out.println("─────────────────────────────────────────────────────────────\n");

        // Генериране на ключ и nonce
        byte[] key = new byte[32];
        String keyStr = "ChaCha20-256bit-Secret-Key!!";
        System.arraycopy(keyStr.getBytes(), 0, key, 0, Math.min(keyStr.length(), 32));

        byte[] nonce = ChaCha20.generateNonce();

        System.out.println("Ключ (256 бита):");
        System.out.println("  " + bytesToHex(key) + "\n");
        System.out.println("Nonce (96 бита):");
        System.out.println("  " + bytesToHex(nonce) + "\n");

        String plaintext = "Поверително съобщение с ChaCha20 криптиране";
        System.out.println("Plaintext: " + plaintext + "\n");

        ChaCha20 cipher = new ChaCha20(key, nonce, 0);
        byte[] encrypted = cipher.crypt(plaintext.getBytes());

        System.out.println("Encrypted (Hex):");
        System.out.println("  " + bytesToHex(encrypted) + "\n");

        ChaCha20 decipher = new ChaCha20(key, nonce, 0);
        String decrypted = new String(decipher.crypt(encrypted));

        System.out.println("Decrypted: " + decrypted);
        System.out.println("Верификация: " + (plaintext.equals(decrypted) ? "✓ УСПЕХ" : "✗ ГРЕШКА") + "\n");

        // Пример 2: Важността на уникален nonce
        System.out.println("─────────────────────────────────────────────────────────────");
        System.out.println("Пример 2: Защо е важен уникалният nonce");
        System.out.println("─────────────────────────────────────────────────────────────\n");

        String msg1 = "Първо съобщение";
        String msg2 = "Второ съобщение";

        // Различни nonce-ове (правилно)
        byte[] nonce1 = ChaCha20.generateNonce();
        byte[] nonce2 = ChaCha20.generateNonce();

        ChaCha20 cipher1 = new ChaCha20(key, nonce1, 0);
        byte[] enc1 = cipher1.encrypt(msg1);

        ChaCha20 cipher2 = new ChaCha20(key, nonce2, 0);
        byte[] enc2 = cipher2.encrypt(msg2);

        System.out.println("✅ ПРАВИЛНО: Уникални nonce-ове за всяко съобщение");
        System.out.println("   Nonce 1:     " + bytesToHex(nonce1));
        System.out.println("   Encrypted 1: " + bytesToHex(enc1));
        System.out.println();
        System.out.println("   Nonce 2:     " + bytesToHex(nonce2));
        System.out.println("   Encrypted 2: " + bytesToHex(enc2));
        System.out.println("   → Шифротекстовете са напълно различни!\n");

        // Пример 3: Криптиране на файл (симулация)
        System.out.println("─────────────────────────────────────────────────────────────");
        System.out.println("Пример 3: Криптиране на файл (симулация)");
        System.out.println("─────────────────────────────────────────────────────────────\n");

        byte[] fileData = new byte[1024 * 100]; // 100 KB
        new java.util.Random().nextBytes(fileData);

        byte[] fileNonce = ChaCha20.generateNonce();
        ChaCha20 fileCipher = new ChaCha20(key, fileNonce, 0);

        long startTime = System.nanoTime();
        byte[] encryptedFile = fileCipher.crypt(fileData);
        long endTime = System.nanoTime();

        double timeMs = (endTime - startTime) / 1_000_000.0;
        double throughput = (fileData.length / (1024.0 * 1024.0)) / (timeMs / 1000.0);

        System.out.println("Размер на файла: " + (fileData.length / 1024) + " KB");
        System.out.printf("Време за криптиране: %.2f ms%n", timeMs);
        System.out.printf("Производителност: %.2f MB/s%n", throughput);
        System.out.println("Верификация: " +
                (fileData.length == encryptedFile.length ? "✓ Размерът е запазен" : "✗"));

        System.out.println("\n═══════════════════════════════════════════════════════════\n");
    }

    /**
     * Демонстрация на Salsa20
     */
    private static void demoSalsa20() {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║                 SALSA20 ДЕМОНСТРАЦИЯ                       ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        System.out.println("✅ Salsa20 е бърз и сигурен (eSTREAM финалист)\n");

        // Пример 1: Основна употреба
        System.out.println("─────────────────────────────────────────────────────────────");
        System.out.println("Пример 1: Основна употреба на Salsa20");
        System.out.println("─────────────────────────────────────────────────────────────\n");

        byte[] key = new byte[32];
        String keyStr = "Salsa20-256-Bit-Secure-Key!!";
        System.arraycopy(keyStr.getBytes(), 0, key, 0, Math.min(keyStr.length(), 32));

        byte[] nonce = Salsa20.generateNonce();

        System.out.println("Ключ (256 бита): " + bytesToHex(key));
        System.out.println("Nonce (64 бита): " + bytesToHex(nonce) + "\n");

        String plaintext = "Salsa20 криптиране на данни";
        System.out.println("Plaintext: " + plaintext + "\n");

        Salsa20 cipher = new Salsa20(key, nonce, 0);
        byte[] encrypted = cipher.encrypt(plaintext);

        System.out.println("Encrypted: " + bytesToHex(encrypted) + "\n");

        Salsa20 decipher = new Salsa20(key, nonce, 0);
        String decrypted = decipher.decrypt(encrypted);

        System.out.println("Decrypted: " + decrypted);
        System.out.println("Верификация: " + (plaintext.equals(decrypted) ? "✓" : "✗") + "\n");

        // Пример 2: Производителност тест
        System.out.println("─────────────────────────────────────────────────────────────");
        System.out.println("Пример 2: Тест на производителност");
        System.out.println("─────────────────────────────────────────────────────────────\n");

        int[] sizes = { 1024, 1024 * 10, 1024 * 100, 1024 * 1024 };
        String[] labels = { "1 KB", "10 KB", "100 KB", "1 MB" };

        System.out.println("Размер    | Време      | Производителност");
        System.out.println("----------|------------|------------------");

        for (int i = 0; i < sizes.length; i++) {
            byte[] data = new byte[sizes[i]];
            new java.util.Random().nextBytes(data);

            Salsa20 perfCipher = new Salsa20(key, Salsa20.generateNonce(), 0);

            long start = System.nanoTime();
            perfCipher.crypt(data);
            long end = System.nanoTime();

            double timeMs = (end - start) / 1_000_000.0;
            double throughput = (sizes[i] / (1024.0 * 1024.0)) / (timeMs / 1000.0);

            System.out.printf("%-9s | %7.2f ms | %10.2f MB/s%n",
                    labels[i], timeMs, throughput);
        }

        System.out.println("\n═══════════════════════════════════════════════════════════\n");
    }

    /**
     * Сравнение на трите шифъра
     */
    private static void compareAll() {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║             СРАВНИТЕЛНА ДЕМОНСТРАЦИЯ                       ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        System.out.println("Криптиране на еднакви данни с всички три шифъра:\n");

        String plaintext = "Тест на всички шифри";
        System.out.println("Plaintext: " + plaintext + "\n");

        // RC4
        byte[] rc4Key = "TestKey".getBytes();
        RC4 rc4 = new RC4(rc4Key);
        byte[] rc4Enc = rc4.encrypt(plaintext);
        System.out.println("RC4:");
        System.out.println("  Ключ:      " + bytesToHex(rc4Key));
        System.out.println("  Encrypted: " + bytesToHex(rc4Enc));
        System.out.println("  Дължина:   " + rc4Enc.length + " байта\n");

        // ChaCha20
        byte[] chachaKey = new byte[32];
        byte[] chachaNonce = ChaCha20.generateNonce();
        System.arraycopy("ChaCha20Key".getBytes(), 0, chachaKey, 0, 11);
        ChaCha20 chacha = new ChaCha20(chachaKey, chachaNonce, 0);
        byte[] chachaEnc = chacha.encrypt(plaintext);
        System.out.println("ChaCha20:");
        System.out.println("  Ключ:      " + bytesToHex(chachaKey).substring(0, 40) + "...");
        System.out.println("  Nonce:     " + bytesToHex(chachaNonce));
        System.out.println("  Encrypted: " + bytesToHex(chachaEnc));
        System.out.println("  Дължина:   " + chachaEnc.length + " байта\n");

        // Salsa20
        byte[] salsaKey = new byte[32];
        byte[] salsaNonce = Salsa20.generateNonce();
        System.arraycopy("Salsa20Key".getBytes(), 0, salsaKey, 0, 10);
        Salsa20 salsa = new Salsa20(salsaKey, salsaNonce, 0);
        byte[] salsaEnc = salsa.encrypt(plaintext);
        System.out.println("Salsa20:");
        System.out.println("  Ключ:      " + bytesToHex(salsaKey).substring(0, 40) + "...");
        System.out.println("  Nonce:     " + bytesToHex(salsaNonce));
        System.out.println("  Encrypted: " + bytesToHex(salsaEnc));
        System.out.println("  Дължина:   " + salsaEnc.length + " байта\n");

        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Забележки:");
        System.out.println("  • Всички шифри запазват дължината на данните");
        System.out.println("  • ChaCha20 и Salsa20 използват nonce за сигурност");
        System.out.println("  • RC4 не използва nonce (уязвимост!)");
        System.out.println("═══════════════════════════════════════════════════════════\n");
    }

    /**
     * Главна програма
     */
    public static void main(String[] args) {
        System.out.println("\n");
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║                                                            ║");
        System.out.println("║      ДЕМОНСТРАЦИЯ НА ПОТОЧНИ ШИФРИ                         ║");
        System.out.println("║      Курсова работа по АSК - Тема 7                        ║");
        System.out.println("║                                                            ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝");
        System.out.println("\n");

        try {
            // RC4 Demo
            demoRC4();
            Thread.sleep(1000);

            // ChaCha20 Demo
            demoChaCha20();
            Thread.sleep(1000);

            // Salsa20 Demo
            demoSalsa20();
            Thread.sleep(1000);

            // Comparison
            compareAll();

        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║                    ЗАКЛЮЧЕНИЕ                              ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        System.out.println("📊 СРАВНИТЕЛНА ТАБЛИЦА:\n");
        System.out.println("┌──────────────┬──────────┬────────────┬──────────────┬──────────┐");
        System.out.println("│ Шифър        │ Сигурност│ Скорост    │ Nonce        │ Препоръка│");
        System.out.println("├──────────────┼──────────┼────────────┼──────────────┼──────────┤");
        System.out.println("│ RC4          │ ❌ Ниска │ Много висока│ ❌ Няма      │ ❌ НЕ    │");
        System.out.println("│ ChaCha20     │ ✅ Висока│ Висока     │ ✅ 96 бита  │ ✅ ДА    │");
        System.out.println("│ Salsa20      │ ✅ Висока│ Много висока│ ✅ 64 бита  │ ✅ ДА    │");
        System.out.println("└──────────────┴──────────┴────────────┴──────────────┴──────────┘\n");

        System.out.println("💡 ПРЕПОРЪКИ:");
        System.out.println("   • За нови проекти използвайте ChaCha20");
        System.out.println("   • Избягвайте RC4 поради сериозни уязвимости");
        System.out.println("   • Винаги използвайте уникален nonce за всяко съобщение");
        System.out.println("   • За AEAD защита комбинирайте с Poly1305\n");

        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Демонстрацията завърши успешно!");
        System.out.println("═══════════════════════════════════════════════════════════\n");
    }
}
