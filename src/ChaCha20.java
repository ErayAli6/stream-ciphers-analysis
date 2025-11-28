/**
 * ChaCha20 Stream Cipher Implementation
 * 
 * ChaCha20 е съвременен поточен шифър, разработен от Daniel J. Bernstein.
 * Това е подобрена версия на Salsa20 с по-добра дифузия.
 * 
 * Спецификация: RFC 8439
 * 
 * Характеристики:
 * - 256-битов ключ
 * - 96-битов nonce (number used once)
 * - 32-битов block counter
 * - 512-битови блокове (64 байта)
 * - 20 рунда (10 double rounds)
 * 
 * ChaCha20 е препоръчван за съвременни приложения и се използва в:
 * - TLS 1.3
 * - WireGuard VPN
 * - OpenSSH
 * - Android криптиране
 * 
 * @author Курсова работа по АSК
 * @version 1.0
 */
public class ChaCha20 {

    // ChaCha20 константи ("expand 32-byte k" в ASCII)
    private static final int[] CONSTANTS = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    private final int[] key; // 8 × 32-bit = 256-bit key
    private final int[] nonce; // 3 × 32-bit = 96-bit nonce
    private int counter; // 32-bit block counter

    /**
     * Конструктор на ChaCha20
     * 
     * @param key     32-байтов (256-битов) ключ
     * @param nonce   12-байтов (96-битов) nonce
     * @param counter начален counter (обикновено 0 или 1)
     * @throws IllegalArgumentException при невалидни размери
     */
    public ChaCha20(byte[] key, byte[] nonce, int counter) {
        if (key.length != 32) {
            throw new IllegalArgumentException("Ключът трябва да е точно 32 байта (256 бита)");
        }
        if (nonce.length != 12) {
            throw new IllegalArgumentException("Nonce трябва да е точно 12 байта (96 бита)");
        }

        this.key = bytesToInts(key);
        this.nonce = bytesToInts(nonce);
        this.counter = counter;
    }

    /**
     * Конструктор с counter = 0
     */
    public ChaCha20(byte[] key, byte[] nonce) {
        this(key, nonce, 0);
    }

    /**
     * Конвертира байтов масив в масив от 32-битови integers (little-endian)
     */
    private int[] bytesToInts(byte[] bytes) {
        int[] ints = new int[bytes.length / 4];
        for (int i = 0; i < ints.length; i++) {
            ints[i] = bytesToInt(bytes, i * 4);
        }
        return ints;
    }

    /**
     * Конвертира 4 байта в 32-битов integer (little-endian)
     */
    private int bytesToInt(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) |
                ((bytes[offset + 1] & 0xFF) << 8) |
                ((bytes[offset + 2] & 0xFF) << 16) |
                ((bytes[offset + 3] & 0xFF) << 24);
    }

    /**
     * Конвертира 32-битов integer в 4 байта (little-endian)
     */
    private void intToBytes(int value, byte[] bytes, int offset) {
        bytes[offset] = (byte) (value & 0xFF);
        bytes[offset + 1] = (byte) ((value >>> 8) & 0xFF);
        bytes[offset + 2] = (byte) ((value >>> 16) & 0xFF);
        bytes[offset + 3] = (byte) ((value >>> 24) & 0xFF);
    }

    /**
     * ChaCha20 Quarter Round операция
     * Основната строителна единица на ChaCha20
     * 
     * Операции:
     * a += b; d ^= a; d <<<= 16;
     * c += d; b ^= c; b <<<= 12;
     * a += b; d ^= a; d <<<= 8;
     * c += d; b ^= c; b <<<= 7;
     */
    private void quarterRound(int[] state, int a, int b, int c, int d) {
        state[a] += state[b];
        state[d] = Integer.rotateLeft(state[d] ^ state[a], 16);

        state[c] += state[d];
        state[b] = Integer.rotateLeft(state[b] ^ state[c], 12);

        state[a] += state[b];
        state[d] = Integer.rotateLeft(state[d] ^ state[a], 8);

        state[c] += state[d];
        state[b] = Integer.rotateLeft(state[b] ^ state[c], 7);
    }

    /**
     * Създава началното състояние на ChaCha20
     * 
     * Структура (4x4 матрица от 32-битови думи):
     * 
     * cccccccc cccccccc cccccccc cccccccc <- Константи
     * kkkkkkkk kkkkkkkk kkkkkkkk kkkkkkkk <- Ключ (част 1)
     * kkkkkkkk kkkkkkkk kkkkkkkk kkkkkkkk <- Ключ (част 2)
     * bbbbbbbb nnnnnnnn nnnnnnnn nnnnnnnn <- Counter + Nonce
     */
    private int[] createInitialState() {
        int[] state = new int[16];

        // Константи (позиции 0-3)
        System.arraycopy(CONSTANTS, 0, state, 0, 4);

        // Ключ (позиции 4-11)
        System.arraycopy(key, 0, state, 4, 8);

        // Counter (позиция 12)
        state[12] = counter;

        // Nonce (позиции 13-15)
        System.arraycopy(nonce, 0, state, 13, 3);

        return state;
    }

    /**
     * ChaCha20 блокова функция
     * Генерира 64 байта keystream от текущото състояние
     * 
     * Извършва 20 рунда (10 двойни рунда):
     * - 4 column rounds
     * - 4 diagonal rounds
     */
    private byte[] chachaBlock() {
        int[] workingState = createInitialState();
        int[] initialState = workingState.clone();

        // 20 рунда = 10 double rounds
        for (int i = 0; i < 10; i++) {
            // Column rounds
            quarterRound(workingState, 0, 4, 8, 12);
            quarterRound(workingState, 1, 5, 9, 13);
            quarterRound(workingState, 2, 6, 10, 14);
            quarterRound(workingState, 3, 7, 11, 15);

            // Diagonal rounds
            quarterRound(workingState, 0, 5, 10, 15);
            quarterRound(workingState, 1, 6, 11, 12);
            quarterRound(workingState, 2, 7, 8, 13);
            quarterRound(workingState, 3, 4, 9, 14);
        }

        // Добавяне на началното състояние (предпазва от атаки)
        for (int i = 0; i < 16; i++) {
            workingState[i] += initialState[i];
        }

        // Конвертиране на 16 integers в 64 байта
        byte[] keystream = new byte[64];
        for (int i = 0; i < 16; i++) {
            intToBytes(workingState[i], keystream, i * 4);
        }

        return keystream;
    }

    /**
     * Криптира/декриптира данни
     * ChaCha20 използва XOR, така че операциите са идентични
     * 
     * @param data данните за обработка
     * @return криптирани/декриптирани данни
     */
    public byte[] crypt(byte[] data) {
        byte[] result = new byte[data.length];
        int offset = 0;

        while (offset < data.length) {
            // Генериране на 64-байтов keystream блок
            byte[] keystream = chachaBlock();

            // XOR на данните с keystream
            int blockSize = Math.min(64, data.length - offset);
            for (int i = 0; i < blockSize; i++) {
                result[offset + i] = (byte) (data[offset + i] ^ keystream[i]);
            }

            offset += blockSize;
            counter++; // Увеличаване на counter за следващия блок
        }

        return result;
    }

    /**
     * Криптира текст
     */
    public byte[] encrypt(String plaintext) {
        return crypt(plaintext.getBytes());
    }

    /**
     * Декриптира данни към текст
     */
    public String decrypt(byte[] ciphertext) {
        return new String(crypt(ciphertext));
    }

    /**
     * Reset на counter-а (за криптиране на ново съобщение със същия ключ/nonce)
     * ВНИМАНИЕ: Никога не използвайте един и същ nonce с един и същ ключ!
     */
    public void resetCounter() {
        this.counter = 0;
    }

    /**
     * Генерира произволен nonce
     */
    public static byte[] generateNonce() {
        byte[] nonce = new byte[12];
        new java.security.SecureRandom().nextBytes(nonce);
        return nonce;
    }

    /**
     * Конвертира байтов масив в hex string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Демонстрационен пример
     */
    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║        ChaCha20 Stream Cipher - Демонстрация              ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        // Генериране на 256-битов ключ
        byte[] key = new byte[32];
        String keyString = "MySecretKey123456789012345678901"; // 32 символа
        System.arraycopy(keyString.getBytes(), 0, key, 0, 32);

        // Генериране на 96-битов nonce
        byte[] nonce = generateNonce();

        System.out.println("🔑 Параметри:");
        System.out.println("   Ключ (Hex):  " + bytesToHex(key));
        System.out.println("   Nonce (Hex): " + bytesToHex(nonce));
        System.out.println("   Counter:     0");
        System.out.println();

        // Тестови данни
        String plaintext = "ChaCha20 е съвременен и сигурен поточен шифър!";

        System.out.println("📝 Оригинален текст:");
        System.out.println("   " + plaintext);
        System.out.println("   Дължина: " + plaintext.getBytes().length + " байта");
        System.out.println();

        // Криптиране
        ChaCha20 cipher = new ChaCha20(key, nonce, 0);
        byte[] encrypted = cipher.encrypt(plaintext);

        System.out.println("🔐 Криптиран (Hex):");
        System.out.println("   " + bytesToHex(encrypted));
        System.out.println();

        // Декриптиране (с нов cipher обект със същите параметри)
        ChaCha20 decipher = new ChaCha20(key, nonce, 0);
        String decrypted = decipher.decrypt(encrypted);

        System.out.println("🔓 Декриптиран текст:");
        System.out.println("   " + decrypted);
        System.out.println();

        // Верификация
        boolean success = plaintext.equals(decrypted);
        System.out.println("✓ Верификация: " + (success ? "УСПЕШНА ✓" : "ГРЕШКА ✗"));
        System.out.println();

        // Демонстрация на важността на nonce
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Демонстрация: Важността на уникален nonce");
        System.out.println("═══════════════════════════════════════════════════════════\n");

        String msg1 = "Първо съобщение";
        String msg2 = "Второ съобщение";

        // С един и същ nonce (ЛОША ПРАКТИКА - само за демонстрация!)
        ChaCha20 cipher1 = new ChaCha20(key, nonce, 0);
        byte[] enc1 = cipher1.encrypt(msg1);

        ChaCha20 cipher2 = new ChaCha20(key, nonce, 0); // Същият nonce!
        byte[] enc2 = cipher2.encrypt(msg2);

        System.out.println("❌ Лоша практика - един и същ nonce:");
        System.out.println("   Съобщение 1: " + bytesToHex(enc1));
        System.out.println("   Съобщение 2: " + bytesToHex(enc2));
        System.out.println();

        // С различни nonce-ове (ДОБРА ПРАКТИКА)
        byte[] nonce1 = generateNonce();
        byte[] nonce2 = generateNonce();

        ChaCha20 cipher3 = new ChaCha20(key, nonce1, 0);
        byte[] enc3 = cipher3.encrypt(msg1);

        ChaCha20 cipher4 = new ChaCha20(key, nonce2, 0);
        byte[] enc4 = cipher4.encrypt(msg2);

        System.out.println("✅ Добра практика - уникални nonce-ове:");
        System.out.println("   Nonce 1:     " + bytesToHex(nonce1));
        System.out.println("   Съобщение 1: " + bytesToHex(enc3));
        System.out.println();
        System.out.println("   Nonce 2:     " + bytesToHex(nonce2));
        System.out.println("   Съобщение 2: " + bytesToHex(enc4));
        System.out.println();

        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("✅ ChaCha20 е препоръчан за съвременни приложения!");
        System.out.println("   • Висока скорост");
        System.out.println("   • Отлична сигурност");
        System.out.println("   • Constant-time имплементация");
        System.out.println("   • Стандартизиран (RFC 8439)");
        System.out.println("═══════════════════════════════════════════════════════════");
    }
}
