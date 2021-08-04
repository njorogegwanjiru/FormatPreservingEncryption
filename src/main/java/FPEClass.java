import com.idealista.fpe.FormatPreservingEncryption;
import com.idealista.fpe.builder.FormatPreservingEncryptionBuilder;
import com.idealista.fpe.component.functions.prf.DefaultPseudoRandomFunction;
import com.idealista.fpe.config.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class FPEClass {

    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
//define tweak to use in encrypt and decrypt functions
        String aTweak = "18AD3A1387A9EB9BD2";

//define an array of characters that define the accepted alphabet for the FPE Builder...you can add more characters to the alphabet
        Alphabet alphabet = new Alphabet() {

            private char[] chars = {' ', '.', ',', '\'', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

            @Override
            public char[] availableCharacters() {
                return chars;
            }

            @Override
            public Integer radix() {
                return chars.length;
            }
        };

//generate a secret key of length 128....it is required that the key is an AES Key
        SecretKey secretKey = generateKey(128);

 //create the FPE Object
        FormatPreservingEncryption formatPreservingEncryption = FormatPreservingEncryptionBuilder
                .ff1Implementation()
//define the Custom Domain (any subset of characters could be used)...could use the default domain but its alphabet only includes the lower case letters of the English alphabet
                .withDomain(new GenericDomain(alphabet, new GenericTransformations(alphabet.availableCharacters()), new GenericTransformations(alphabet.availableCharacters())))
//use default Pseudo Random Function to ensure that the same cipher function is persisted & always used; ensuring encryptions & decryptions match
//different PRFs won't return similar results
                .withDefaultPseudoRandomFunction(convertSecretKeyToByteArray(secretKey))
//The minimum length of input text
                .withLengthRange(new LengthRange(2, 100))
                .build();
//define scanner
        Scanner scanner = new Scanner(System.in);
//get user options
        System.out.println("Enter '1' to encrypt your input or '2' to decrypt your input");
        int userOption = scanner.nextInt();
        scanner.nextLine();

//encrypt or decrypt based on user choice & print input and output
        if (userOption == 1) {
            System.out.println("Enter input to encrypt here: ");
            String inputToEncrypt = scanner.nextLine();
            String cipherText = formatPreservingEncryption.encrypt(String.valueOf(inputToEncrypt), aTweak.getBytes());

            System.out.println("You entered:" + inputToEncrypt);
            System.out.println("Encrypted value:" + cipherText);

        } else if (userOption == 2) {
            System.out.println("Enter input to decrypt here: ");
            String inputToDecrypt = scanner.nextLine();
            String plainText = formatPreservingEncryption.decrypt(String.valueOf(inputToDecrypt), aTweak.getBytes());

            System.out.println("You entered:" + inputToDecrypt);
            System.out.println("Decrypted value:" + plainText);

        } else {
            System.out.println("Incorrect Input, Must be '1' 0r '2'");
        }

    }
//method to generate secret key, takes an int argument that defines the length of the key
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        final String salt = "SaltSalt";
//use AES algorithm
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//Generate a seed to aid in generating the encryption/decryption key
// A seed is a number (or vector) used to initialize a pseudorandom number generator.
// When a secret encryption/decryption key is pseudorandomly generated, having the seed will allow one to obtain the key
// If the same random seed is deliberately shared, it becomes a secret key,
// so two or more systems using matching pseudorandom number algorithms and matching seeds can generate matching sequences of non-repeating numbers
// this is how multiple runs of the program all generate the same key hence the consistency.
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(salt.getBytes("UTF-8"));
//generate the key
        keyGenerator.init(n, secureRandom);

        return keyGenerator.generateKey();
    }
//convert the secret key to get its value in a byte array to pass to the PRF Builder
    public static byte[] convertSecretKeyToByteArray(SecretKey secretKey) {
        return secretKey.getEncoded();
    }


}
