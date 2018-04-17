/**
 * Given: a ciphertext that has been decrypted twice with different DES keys with ECB/PKCS5Padding
 * Given: the 2 keys (that were used for encryption) have their last 3 bytes missing
 * Finds the original text and the full keys.
 * The key and the ciphertext are originally in HEX format but have to be
 * transformed into byte array to be operated on.
 * Execution time: around 5 minutes
 */

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class Q4 {

    // DES decryption cipher
    private Cipher dcipher;
    // Holds all the possible ciphertexts that have to be decrypted once more to get
    // the plaintext
    private ArrayList<byte[]> possibleDecryptions;
    // Holds all possible plaintexts
    private ArrayList<String> printableDecryptions;
    // corrupted key used in encryption
    private byte[] key;

    /**
     * @param keybytes - the DES key, the decryption method depends on it
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     */
    public Q4(byte[] keybytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        SecretKey key = new SecretKeySpec(keybytes, "DES");
        dcipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        dcipher.init(Cipher.DECRYPT_MODE, key);
        printableDecryptions = new ArrayList<String>();
        possibleDecryptions = new ArrayList<byte[]>();
        this.key = keybytes;
    }

    /**
     * @param databytes: ciphertext that need to be decrypted
     * @return true if there are no bad exceptions after the decryption and the
     * resultant text is without padding and is a multiple of 8
     * only true for the first decryption because the resultant is a ciphertext with
     * padding so it definitely will be a multiple of 8, otherwise it won't
     * be valid
     */
    public boolean paddingQuery1stDecryption(byte[] databytes) {
        boolean m = false;
        try {
            byte[] b = dcipher.doFinal(databytes);
            // b.length < 20 &&
            if (b.length % 8 == 0) {
                m = true;
            }
        } catch (IllegalBlockSizeException e) {
            return false;
        } catch (BadPaddingException e) {
            return false;
        }
        return m;
    }

    /**
     * @param databytes: ciphertext that need to be decrypted
     * @return true if there are no bad exceptions after the decryption and the
     * resultant text is without padding. Since it is a plaintext it doesn't need to be a multiple of 8.
     */
    public boolean paddingQuery2ndDecryption(byte[] databytes) {
        try {
            dcipher.doFinal(databytes);
        } catch (IllegalBlockSizeException e) {
            return false;
        } catch (BadPaddingException e) {
            return false;
        }
        return true;
    }

    /**
     * @param databytes the ciphertext
     * @return the decrypted ciphertext
     */
    public byte[] decrypt(byte[] databytes) {
        byte[] dec = null;
        try {
            dec = dcipher.doFinal(databytes);
        } catch (IllegalBlockSizeException e) {
            System.out.println(e);
        } catch (BadPaddingException e) {
            // e.printStackTrace();
        }
        return dec;
    }

    /*
     * It should only return true when all the characters are printable, and false
     */
    public static boolean printable(byte[] databytes) {
        int currentByte;
        int len = databytes.length;
        for (int i = 0; i < len - 1; i++) {
            currentByte = (int) databytes[i];
            if (currentByte < 32 || currentByte > 127) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param ciphertext      the ciphertext to be brute forced
     * @param firstDecryption padding query selection depends on the decryption order
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public void bruteForce3(byte[] ciphertext, boolean firstDecryption)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {

        boolean answer = false;
        byte[] possiblePlain;

        int count = 0;
        for (int i = 0; i < 256; i++) {
            key[5] = (byte) i;
            for (int j = 0; j < 256; j++) {
                key[6] = (byte) j;
                for (int k = 0; k < 256; k++) {
                    key[7] = (byte) k;
                    Q4 dc = new Q4(key);
                    if (firstDecryption) {
                        answer = dc.paddingQuery1stDecryption(ciphertext);
                    }
                    if (!firstDecryption) {
                        answer = dc.paddingQuery2ndDecryption(ciphertext);
                    }
                    if (answer) {
                        count++;
                        possiblePlain = dc.decrypt(ciphertext);
                        possibleDecryptions.add(possiblePlain);
                        if (Q4.printable(possiblePlain)) {
                            String text = new String(possiblePlain);
                            printableDecryptions.add(text);
                            System.out.print("Possible decryption: " + text);
                            System.out.println("    Key = " + DatatypeConverter.printHexBinary(key));
                        } else if(firstDecryption) {
                            System.out.println("Ciphertext: " + DatatypeConverter.printHexBinary(possiblePlain));
                        }
                    }
                }
            }
        }
    }

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            IOException {
        // the given DES keys with their last 3 bytes corrupted
        byte[] keybytes1 = DatatypeConverter.parseHexBinary("253e6b9268000000");
        byte[] keybytes2 = DatatypeConverter.parseHexBinary("29f74fb0e0000000");
        // the twice encrypted ciphertext
        byte[] ciphertext = DatatypeConverter.parseHexBinary("7cfec80c4883df144cc1c4b168dd841c631d5fdf77254fff");

        // getting all the possible original ciphertexts (those encrypted initially)
        // First decryption with the second key
        Q4 firstDecr = new Q4(keybytes2);
        firstDecr.bruteForce3(ciphertext, true);
        // gives 8 because there are 8 different keys that can decrypt the ciphertext to the first one
        System.out.println("PossibleDecryptions size of firstDecr: " + firstDecr.possibleDecryptions.size());
        // this should give zero, because ciphertext shouldn't be printable
        System.out.println("PrintableDecryptions size of firstDecr: " + firstDecr.printableDecryptions.size());


        // Second decryption with first key = get the plaintext
        Q4 secondDecr = new Q4(keybytes1);
        // all ciphertext are the same, the keys are different
        byte[] tempCipher = firstDecr.possibleDecryptions.get(0);
        secondDecr.bruteForce3(tempCipher, false);
        System.out.println("Second decryption for plaintext");

        System.out.println("PossibleDecriptions size of secondDecr: " + secondDecr.possibleDecryptions.size());
        System.out.println("PrintableDecriptions size of secondDecr: " + secondDecr.printableDecryptions.size());

    }

}
