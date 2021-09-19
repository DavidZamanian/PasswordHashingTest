import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
public class Hashing {


    /**
     * 1. Take the password as input from the user and generate a secure hash from it and then store the hash in the database/local storage
     *    (U ALSO HAVE TO STORE THE ORIGINAL SALT OTHERWISE THE HASH WILL BE DIFFERENT).
     * 2. When a user tries to log in, the password is hashed again and compared to the stored hash, if it matches it is the same password and the user can log in.
     *
     *
     */


    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        String  originalPassword = "password";
        String generatedSecuredPasswordHash = generateStrongPasswordHash(originalPassword);
        System.out.println(generatedSecuredPasswordHash);

        boolean matched = validatePassword("password", generatedSecuredPasswordHash);
        System.out.println(matched);

        matched = validatePassword("password1", generatedSecuredPasswordHash);
        System.out.println(matched);
    }

    /**
     *
     * Uses the PBKDF2WithHmacSHA1 algorithm to generate the hash.
     * - PBEKeySpec spec generates a more advanced password with the input password (as a char array), a salt and a number of iterations.
     * - Then the hash is generated with the PBKDF2WithHmacSHA1 algorithm and the advanced password
     * - The hash is then saved in a string together with the iterations and the salt (They are needed later for validating the password)
     *
     *  iterations is the number of times the password is hashed
     *  salt protects against rainbow tables
     */


    private static String generateStrongPasswordHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        int iterations = 1000;
        char[] chars = password.toCharArray();
        byte[] salt = getSalt();

        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return iterations + ":" + toHex(salt) + ":" + toHex(hash);
    }

    /**
     * SHA1RNG uses the SHA1 hash function to generate a stream of random numbers called "salt".
     *
     */

    private static byte[] getSalt() throws NoSuchAlgorithmException
    {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        System.out.println("Salt: " + Arrays.toString(salt));
        return salt;
    }

    /**
     * Takes an array of bytes and returns that array in hexadecimal
     *
     */

    private static String toHex(byte[] array) throws NoSuchAlgorithmException
    {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
        {
            return String.format("%0"  +paddingLength + "d", 0) + hex;
        }else{
            return hex;
        }
    }

    /**
     * validatePassword takes the input password and the stored password hash and returns true or false if both hashes match
     *  1. It splits up the stored password hash into the iterations, salt and hash.
     *  2. It creates an advanced password from the input password together with the salt and iterations (and the length of the hash) of the stored password.
     *  3. Then it generates a new hash from the new advanced password
     *  4. Now it compares the new hash from the input password with the stored hash, if they are equal it returns true else false.
     */

    private static boolean validatePassword(String originalPassword, String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        String[] parts = storedPassword.split(":");
        int iterations = Integer.parseInt(parts[0]);
        byte[] salt = fromHex(parts[1]);
        byte[] hash = fromHex(parts[2]);

        PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt, iterations, hash.length * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] testHash = skf.generateSecret(spec).getEncoded();

        int diff = hash.length ^ testHash.length;
        for(int i = 0; i < hash.length && i < testHash.length; i++)
        {
            diff |= hash[i] ^ testHash[i];
        }
        return diff == 0;
    }

    /**
     * Takes a hex as input and returns it as an array of bytes.
     */

    private static byte[] fromHex(String hex) throws NoSuchAlgorithmException
    {
        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i<bytes.length ;i++)
        {
            bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

}
