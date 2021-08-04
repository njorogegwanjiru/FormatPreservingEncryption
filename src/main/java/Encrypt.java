import com.idealista.fpe.FormatPreservingEncryption;
import com.idealista.fpe.builder.FormatPreservingEncryptionBuilder;
import com.idealista.fpe.config.Alphabet;
import com.idealista.fpe.config.GenericDomain;
import com.idealista.fpe.config.GenericTransformations;
import com.idealista.fpe.config.LengthRange;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Encrypt {
    private static final String aTweak = "1867687968866456789";
    private static final char[] specialCharacters = {'@', '(', ')', ' ', '.', '*', '+', '-', '#', '[', ']', '|', '{', '}', ',', '/', '"', '"', ';', ':', '$', '%'};
    private static SecretKey secretKey;

    static {
        try {
            secretKey = generateKey(128);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    static String ssnPattern = "^(?!666|000|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0{4})\\d{4}$";
    static String phonePattern = "^(\\+\\d{1,2}\\s)?\\(?\\d{3}\\)?[\\s.-]\\d{3}[\\s.-]\\d{4}$";
    static String emailPattern = "^([\\w-\\.]+){1,64}@([\\w&&[^_]]+){2,255}.[a-z,A-Z]{2,}$";
    static String lettersOnlyPattern = "^([a-zA-z/\\\\''(),\\-\\s]{2,255})$";
    static String numbersOnlyPattern = "\\d+";
    static String alphanumericsPattern = "^[a-zA-Z0-9]*$";
    static String timestampPattern = "\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}";

    static char[] numbersAlphabet = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    static char[] lettersOnlyAlphabet = new char[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
    static char[] alphanumericsAlphabet = new char[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};


    // method to generate secret key, takes an int argument that defines the length of the key
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        final String salt = "SaltSalt";
// use AES algorithm
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
// Generate a seed to aid in generating the encryption/decryption key
// A seed is a number (or vector) used to initialize a pseudorandom number generator.
// When a secret encryption/decryption key is pseudorandomly generated, having the seed will allow you to obtain the key
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

    //dynamically define alphabet to use based on user input
    public static Alphabet defineAlphabet(char[] alphabetChars) {
        Alphabet alphabet = new Alphabet() {

            private final char[] chars = alphabetChars;

            @Override
            public char[] availableCharacters() {
                return chars;
            }

            @Override
            public Integer radix() {
                return chars.length;
            }
        };
        return alphabet;

    }

    public static FormatPreservingEncryption createFPEObject(Alphabet alphabet) {
        //initialize the FPE Object
        return FormatPreservingEncryptionBuilder
                .ff1Implementation()
//define the Custom Domain (any subset of characters could be used)...could use the default domain but its alphabet only includes the lower case letters of the English alphabet
                .withDomain(new GenericDomain(alphabet, new GenericTransformations(alphabet.availableCharacters()), new GenericTransformations(alphabet.availableCharacters())))
//use default Pseudo Random Function to ensure that the same cipher function is persisted & always used; ensuring encryptions & decryptions match
//different PRFs won't return similar results
                .withDefaultPseudoRandomFunction(convertSecretKeyToByteArray(secretKey))
//The minimum length of input text
                .withLengthRange(new LengthRange(2, 100))
                .build();

    }

    public static boolean containsSpecialCharacters(String inputString) {
        if (inputString == null) {
            return false;
        }
        Pattern regularCharacters = Pattern.compile("[^A-Za-z0-9]");
        Matcher matcher = regularCharacters.matcher(inputString);

        return matcher.find();
    }

    public static boolean isSpecialCharacter(char character) {
        List<Character> characters = new ArrayList<>();
        for (char c : specialCharacters) {
            characters.add(c);
        }
        return characters.contains(character);
    }

    public static boolean isTimestamp(String input) {
        return input.matches(timestampPattern);
    }

    public static boolean isNotUTFEncoded(char character) {
        boolean utfEncoded = true;
        byte charBytes = (byte) character;

        if ((charBytes & 0x80) != 0) {
            utfEncoded = true;
        } else {
            utfEncoded = false;
        }
        return utfEncoded;
    }

    public static void encryptHelper(Alphabet alphabet, String inputToEncrypt) throws ParseException {
        FormatPreservingEncryption formatPreservingEncryption = createFPEObject(alphabet);

        StringBuilder nonSpecialCharacters = new StringBuilder();
        StringBuilder cipher = new StringBuilder();

        if (isTimestamp(inputToEncrypt)) {
            long unixTimestamp = getUnixTimestamp(inputToEncrypt);
            cipher.append(formatPreservingEncryption.encrypt(String.valueOf(unixTimestamp * 3600), aTweak.getBytes()));
        }
        else {
            if (containsSpecialCharacters(inputToEncrypt)) {
                LinkedHashMap<Integer, Character> specialCharactersIndexesMap = new LinkedHashMap<>();
                char[] inputChars = inputToEncrypt.toCharArray();

                for (int i = 0; i < inputChars.length; i++) {
                    char c = inputChars[i];
                    if (isSpecialCharacter(c)) {
                        specialCharactersIndexesMap.put(i, c);
                    } else if (isNotUTFEncoded(c)) {
                        specialCharactersIndexesMap.put(i, c);
                        System.out.println(c);
                    } else {
                        nonSpecialCharacters.append(String.valueOf(c));
                    }
                }
                //encrypt the non special characters
                String encryptedNonSpecialCharacters = formatPreservingEncryption.encrypt(nonSpecialCharacters.toString(), aTweak.getBytes());
                cipher.append(encryptedNonSpecialCharacters);

                //add the special characters back
                Set<Integer> keys = specialCharactersIndexesMap.keySet();
                for (Integer key : keys) {
                    cipher.insert(key, (Object) specialCharactersIndexesMap.get(key));
                }
            } else {
                cipher.append(formatPreservingEncryption.encrypt(inputToEncrypt, aTweak.getBytes()));
            }
        }
        String cipherText = cipher.toString();
        System.out.println("Input: " + inputToEncrypt);
        System.out.println("Encrypted Text: " + cipherText);
    }

    public static long getUnixTimestamp(String input) throws ParseException {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date date = format.parse(input);
        return date.getTime() / 1000;
    }

    public static void main(String[] args) throws ParseException {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter inputToEncrypt to encrypt here: ");
        String inputToEncrypt = scanner.nextLine();

        Alphabet alphabet;
        if (inputToEncrypt.matches(ssnPattern)) {
            System.out.println("ssn");
            alphabet = defineAlphabet(numbersAlphabet);
        } else if (inputToEncrypt.matches(phonePattern)) {
            System.out.println("phone");
            alphabet = defineAlphabet(numbersAlphabet);
        } else if (inputToEncrypt.matches(lettersOnlyPattern)) {
            System.out.println("letters only");
            alphabet = defineAlphabet(lettersOnlyAlphabet);
        } else if (inputToEncrypt.matches(numbersOnlyPattern)) {
            System.out.println("numbers only");
            alphabet = defineAlphabet(numbersAlphabet);
        } else if (inputToEncrypt.matches(emailPattern) && inputToEncrypt.matches(".*\\d+.*")) {
            System.out.println("email with digits");
            alphabet = defineAlphabet(alphanumericsAlphabet);
        } else if (inputToEncrypt.matches(emailPattern) && !inputToEncrypt.matches(".*\\d+.*")) {
            System.out.println("email without digits");
            alphabet = defineAlphabet(lettersOnlyAlphabet);
        } else if (inputToEncrypt.matches(alphanumericsPattern)) {
            System.out.println("alphanumerics");
            alphabet = defineAlphabet(alphanumericsAlphabet);
        } else if (isTimestamp(inputToEncrypt)) {
            System.out.println("timestamp");
            alphabet = defineAlphabet(numbersAlphabet);
        } else {
            System.out.println("last option");
            alphabet = defineAlphabet(alphanumericsAlphabet);
        }

        encryptHelper(alphabet, inputToEncrypt);


    }


}
