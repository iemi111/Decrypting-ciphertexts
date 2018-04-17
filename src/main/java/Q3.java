import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class Q3 {

    private String cipher1 = "RIGWDZLIYJ";
    private String cipher2 = "DFDPVHFKIC";
    // holds the bytes for the one-time pad key
    private final char[] key = new char[10];

    /**
     * goes through all letters and compares the 'key' if there is not a match it
     * exits the loop and boolean becomes false - no match.
     * Calculates the difference between both words and both ciphertexts
     * to gain the key as it was used for both ciphertexts.
     * The difference has to be the same for every letter, which gives us the key.
     *
     * @param w1 one word from dictionary
     * @param w2 another word from dictionary
     * @param c1 ciphertext of first word
     * @param c2 ciphertext of second word
     * @return true if there is a match in the key of two different words with the given ciphertexts
     */
    private boolean calculate(String w1, String w2, String c1, String c2) {
        boolean equal = true;

        for (int i = 0; i < 10; i++) {
            // value for letter difference in ciphertext and plaintext
            int m1 = Math.abs((w1.charAt(i) - c1.charAt(i)));
            int m2 = Math.abs((w2.charAt(i) - c2.charAt(i)));
            // if both substitutions match assign the value for the key shift
            if (m1 == m2) {
                key[i] = (char) ((int) ('A') + m1);

                // checks if both words encryption addition was
                // overflowing (use of mod26) - shift led to a number larger than 25
            } else {
                int p1 = 26 - Math.abs((w1.charAt(i) - c1.charAt(i)));
                int p2 = 26 - Math.abs((w2.charAt(i) - c2.charAt(i)));
                if (p1 == p2 || p1 == m2 || p2 == m1) {
                    key[i] = (char) ((int) ('A') + p1);
                    // checks cases when one word does need the use of mod26 and the other doesn't
                } else {
                    equal = false;
                    break;
                }
            }
        }
        return equal;
    }

    /**
     * Goes through all words in the dictionary and compares two pairs of words at time with the given cipher texts
     *
     * @param str array holding all words from the dictionary with the same size words
     * @throws IOException
     */
    public void findKey(String[] str) {

        String word1;
        String word2;

        for (int i = 0; i < 35529; i++) {
            word1 = str[i];
            for (int j = 0; j < 35529; j++) {
                word2 = str[j];

                boolean match = calculate(word1, word2, cipher1, cipher2);
                // if there's no match, try other pair
                if (!match) {
                    boolean stop = calculate(word1, word2, cipher2, cipher1);
                    // if key is found, stop loop and print key and words
                    if (stop) {
                        System.out.println("Done!");
                        System.out.println("Key: " + new String(key));
                        System.out.println("Words: " + word1 + ", " + word2);
                        break;
                    }
                }
            }
        }
    }

    public static void main(String[] args) throws IOException {

        Q3 q3 = new Q3();

        // put all words from the dictionary into a string array
        FileReader fileR = new FileReader("src/main/resources/10letterwordslist.txt");
        BufferedReader bufr = new BufferedReader(fileR);
        String[] allWords = new String[35529];
        for (int i = 0; i < 35529; i++) {
            allWords[i] = bufr.readLine();
        }
        bufr.close();

        q3.findKey(allWords);
    }

}
