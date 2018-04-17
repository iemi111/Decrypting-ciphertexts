/*
 * Question 2:
 * Decrypt a ciphertext (an English word) encrypted using RSA/ECB/NoPadding, given the RSA public key
 * Uses dictionary attack
 */

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

public class Q2 {

    private RSAPublicKeySpec publicKeySpecs;
    // Encryption using RSA with ECB and NoPadding
    private Cipher publicKeyCipher;
    // plaintext that needs to be found
    String found;

    public Q2() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException {


        // the modulus
        BigInteger modulus = new BigInteger(
                "7807258627376568178037190048757571987961286635800337736642937427258865611274481654989422492406423553708712834911779798138411429756168288656674624317533797");
        // the exponent
        BigInteger exponent = new BigInteger("65537");
        this.publicKeySpecs = new RSAPublicKeySpec(modulus, exponent);

        // creating the key object using defined public key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(publicKeySpecs);
        // creating encryption using this specific public key
        publicKeyCipher = Cipher.getInstance("RSA/ECB/NoPadding");
        publicKeyCipher.init(Cipher.ENCRYPT_MODE, key);
    }

    /**
     * english.txt - English dictionary
     * Encrypts all words from the dictionary and compares the ciphertext from each
     * word to the one that was given in the beginning
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public void dictionaryAttack() throws IOException, IllegalBlockSizeException, BadPaddingException {

        FileReader fileR = new FileReader("src/main/resources/english.txt");
        BufferedReader bufr = new BufferedReader(fileR);

        // Given ciphertext in question 2
        byte[] ciphertext = DatatypeConverter.parseHexBinary(
                "6D0E14E8D8AB6CDEC790CF4B16F802DA20AE474448865169707E185D5679C3EA91861FD2B14F2D1837618996D0718D025877A17763244E58A2601CE911961E3D");

        //int count = 1;
        String line = bufr.readLine();
        while (line != null) {
            // encrypt word
            byte[] m = publicKeyCipher.doFinal(line.getBytes());
            // System.out.println(count + " : " + line); - prints all words with their corresponding ciphertexts
            // System.out.println(count + " : " + DatatypeConverter.printHexBinary(m));
            // compare the two ciphertexts
            if (Arrays.equals(ciphertext, m)) {
                found = line;
            }
            line = bufr.readLine();
            //count++;
        }
        bufr.close();
    }

    public BigInteger getModulus() {
        return publicKeySpecs.getModulus();
    }

    public BigInteger getExponent() {
        return publicKeySpecs.getPublicExponent();
    }

    public static void main(String[] args)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, IOException {

        Q2 q2 = new Q2();

        System.out.println("Exponent = " + q2.getExponent().toString());
        System.out.println("Modulus = " + q2.getModulus().toString());

        q2.dictionaryAttack();
        System.out.print("Plaintext: " + q2.found);

    }

}
