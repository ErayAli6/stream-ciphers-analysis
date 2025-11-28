/**
 * Salsa20 Stream Cipher Implementation
 * 
 * Salsa20 е поточен шифър, разработен от Daniel J. Bernstein.
 * Това е предшественикът на ChaCha20 и също се базира на ARX конструкция.
 * 
 * Финалист в eSTREAM конкурса (2008)
 * 
 * Характеристики:
 * - 256-битов ключ (или 128)
 * - 64-битов nonce
 * - 64-битов block counter
 * - 512-битови блокове (64 байта)
 * - 20 рунда (пълна версия), 12 или 8 рунда (намалени версии)
 * 
 * Приложения:
 * - NaCl криптографска библиотека
 * - Различни файлови системи с криптиране
 * 
 * @author Курсова работа по АSК
 * @version 1.0
 */
public class Salsa20 {

    // Salsa20 константи ("expand 32-byte k" в ASCII)
    private static final int[] CONSTANTS = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    private final int[] key; // 8 × 32-bit = 256-bit key
    private final int[] nonce; // 2 × 32-bit = 64-bit nonce
    private long counter; // 64-bit block counter

    /**
     * Конструктор на Salsa20
     * 
     * @param key     32-байтов (256-битов) ключ
     * @param nonce   8-байтов (64-битов) nonce
     * @param counter начален counter (обикновено 0)
     * @throws IllegalArgumentException при невалидни размери
     */
    public Salsa20(byte[] key, byte[] nonce, long counter) {
        if (key.length != 32) {
            throw new IllegalArgumentException("Ключът трябва да е точно 32 байта (256 бита)");
        }
        if (nonce.length != 8) {
            throw new IllegalArgumentException("Nonce трябва да е точно 8 байта (64 бита)");
        }

        this.key = bytesToInts(key);
        this.nonce = bytesToInts(nonce);
        this.counter = counter;
    }

    /**
     * Конструктор с counter = 0
     */
    public Salsa20(byte[] key, byte[] nonce) {
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
     * Salsa20 Quarter Round операция
     * 
     * Малко различна от ChaCha20:
     * b ^= ((a + d) <<< 7);
     * c ^= ((b + a) <<< 9);
     * d ^= ((c + b) <<< 13);
     * a ^= ((d + c) <<< 18);
     */
    private void quarterRound(int[] state, int a, int b, int c, int d) {
        state[b] ^= Integer.rotateLeft(state[a] + state[d], 7);
        state[c] ^= Integer.rotateLeft(state[b] + state[a], 9);
        state[d] ^= Integer.rotateLeft(state[c] + state[b], 13);
        state[a] ^= Integer.rotateLeft(state[d] + state[c], 18);
    }

    /**
     * Rowround - прилага quarter round на всеки ред
     */
    private void rowRound(int[] state) {
        quarterRound(state, 0, 1, 2, 3);
        quarterRound(state, 5, 6, 7, 4);
        quarterRound(state, 10, 11, 8, 9);
        quarterRound(state, 15, 12, 13, 14);
    }

    /**
     * Columnround - прилага quarter round на всяка колона
     */
    private void columnRound(int[] state) {
        quarterRound(state, 0, 4, 8, 12);
        quarterRound(state, 5, 9, 13, 1);
        quarterRound(state, 10, 14, 2, 6);
        quarterRound(state, 15, 3, 7, 11);
    }

    /**
     * Doubleround - комбинация от columnround и rowround
     */
    private void doubleRound(int[] state) {
        columnRound(state);
        rowRound(state);
    }

    /**
     * Създава началното състояние на Salsa20
     * 
     * Структура (4x4 матрица от 32-битови думи):
     * 
     * cccccccc kkkkkkkk kkkkkkkk kkkkkkkk
     * kkkkkkkk cccccccc nnnnnnnn nnnnnnnn
     * bbbbbbbb bbbbbbbb cccccccc kkkkkkkk
     * kkkkkkkk kkkkkkkk kkkkkkkk cccccccc
     * 
     * c = константи, k = ключ, n = nonce, b = block counter
     */
    private int[] createInitialState() {
        int[] state = new int[16];

        // Структура на Salsa20
        state[0] = CONSTANTS[0];
        state[1] = key[0];
        state[2] = key[1];
        state[3] = key[2];
        state[4] = key[3];
        state[5] = CONSTANTS[1];
        state[6] = nonce[0];
        state[7] = nonce[1];
        state[8] = (int) counter; // Lower 32 bits
        state[9] = (int) (counter >>> 32); // Upper 32 bits
        state[10] = CONSTANTS[2];
        state[11] = key[4];
        state[12] = key[5];
        state[13] = key[6];
        state[14] = key[7];
        state[15] = CONSTANTS[3];

        return state;
    }

    /**
     * Salsa20 блокова функция
     * Генерира 64 байта keystream
     * 
     * Извършва 20 рунда (10 double rounds)
     */
    private byte[] salsa20Block() {
        int[] workingState = createInitialState();
        int[] initialState = workingState.clone();

        // 20 рунда = 10 double rounds
        for (int i = 0; i < 10; i++) {
            doubleRound(workingState);
        }

        // Добавяне на началното състояние
        for (int i = 0; i < 16; i++) {
            workingState[i] += initialState[i];
        }

        // Конвертиране в байтове
        byte[] keystream = new byte[64];
        for (int i = 0; i < 16; i++) {
            intToBytes(workingState[i], keystream, i * 4);
        }

        return keystream;
    }

    /**
     * Криптира/декриптира данни
     * 
     * @param data данните за обработка
     * @return криптирани/декриптирани данни
     */
    public byte[] crypt(byte[] data) {
        byte[] result = new byte[data.length];
        int offset = 0;

        while (offset < data.length) {
            // Генериране на 64-байтов keystream блок
            byte[] keystream = salsa20Block();

            // XOR на данните с keystream
            int blockSize = Math.min(64, data.length - offset);
            for (int i = 0; i < blockSize; i++) {
                result[offset + i] = (byte) (data[offset + i] ^ keystream[i]);
            }

            offset += blockSize;
            counter++; // Увеличаване на counter
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
     * Reset на counter-а
     */
    public void resetCounter() {
        this.counter = 0;
    }

    /**
     * Генерира произволен nonce
     */
    public static byte[] generateNonce() {
        byte[] nonce = new byte[8];
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
        System.out.println("║         Salsa20 Stream Cipher - Демонстрация              ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");

        // Генериране на 256-битов ключ
        byte[] key = new byte[32];
        String keyString = "Salsa20SecretKey12345678901234"; // 32 символа
        System.arraycopy(keyString.getBytes(), 0, key, 0, 32);

        // Генериране на 64-битов nonce
        byte[] nonce = generateNonce();

        System.out.println("🔑 Параметри:");
        System.out.println("   Ключ (Hex):  " + bytesToHex(key));
        System.out.println("   Nonce (Hex): " + bytesToHex(nonce));
        System.out.println("   Counter:     0");
        System.out.println();

        // Тестови данни
        String plaintext = "Salsa20 е бърз и сигурен поточен шифър!";

        System.out.println("📝 Оригинален текст:");
        System.out.println("   " + plaintext);
        System.out.println("   Дължина: " + plaintext.getBytes().length + " байта");
        System.out.println();

        // Криптиране
        Salsa20 cipher = new Salsa20(key, nonce, 0);
        byte[] encrypted = cipher.encrypt(plaintext);

        System.out.println("🔐 Криптиран (Hex):");
        System.out.println("   " + bytesToHex(encrypted));
        System.out.println();

        // Декриптиране
        Salsa20 decipher = new Salsa20(key, nonce, 0);
        String decrypted = decipher.decrypt(encrypted);

        System.out.println("🔓 Декриптиран текст:");
        System.out.println("   " + decrypted);
        System.out.println();

        // Верификация
        boolean success = plaintext.equals(decrypted);
        System.out.println("✓ Верификация: " + (success ? "УСПЕШНА ✓" : "ГРЕШКА ✗"));
        System.out.println();

        // Сравнение с различни варианти
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Варианти на Salsa20:");
        System.out.println("═══════════════════════════════════════════════════════════\n");

        System.out.println("   • Salsa20/20 - пълна версия с 20 рунда (тази имплементация)");
        System.out.println("   • Salsa20/12 - 12 рунда (по-бърз, все още сигурен)");
        System.out.println("   • Salsa20/8  - 8 рунда (много бърз, по-малко сигурен)");
        System.out.println();

        // Производителност тест
        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("Тест на производителност:");
        System.out.println("═══════════════════════════════════════════════════════════\n");

        byte[] testData = new byte[1024 * 1024]; // 1 MB
        new java.util.Random().nextBytes(testData);

        Salsa20 perfCipher = new Salsa20(key, nonce, 0);

        long startTime = System.nanoTime();
        byte[] encryptedData = perfCipher.crypt(testData);
        long endTime = System.nanoTime();

        double timeSec = (endTime - startTime) / 1_000_000_000.0;
        double throughput = testData.length / (1024.0 * 1024.0) / timeSec;

        System.out.printf("   Обем данни:      %d байта (1 MB)%n", testData.length);
        System.out.printf("   Време:           %.3f секунди%n", timeSec);
        System.out.printf("   Производителност: %.2f MB/s%n", throughput);
        System.out.println();

        System.out.println("═══════════════════════════════════════════════════════════");
        System.out.println("✅ Salsa20 характеристики:");
        System.out.println("   • Много висока скорост");
        System.out.println("   • Доказана сигурност");
        System.out.println("   • Основа за ChaCha20");
        System.out.println("   • Финалист в eSTREAM");
        System.out.println("═══════════════════════════════════════════════════════════");
    }
}
