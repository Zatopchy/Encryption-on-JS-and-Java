import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class App {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public App() throws NoSuchAlgorithmException {
//      Create public and private keys
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public void writeToFile(String path, String key) throws IOException {
//      Writing keys to a file
        File f = new File(path);
        f.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(f);

        byte[] buffer = key.getBytes();
        fos.write(buffer, 0, buffer.length);
        fos.flush();
        fos.close();
    }

    //  Content encryption
    public static void encryptFile(String path, String path2, String publicKey) throws IOException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException {
        File file = new File(path);
        File file2 = new File(path2);
        file.getParentFile().mkdirs();
        file2.getParentFile().mkdirs();

        try (
                FileOutputStream outputStream = new FileOutputStream(file2);
        ) {
//          Initializing the encryption method
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));

            byte[] inputArray = Files.readAllBytes(file.toPath());
            int inputLength = inputArray.length;
            int MAX_ENCRYPT_BLOCK = 117;
            int offSet = 0;
            byte[] resultBytes = {};
            byte[] cache = {};
//          Content encryption block by block
            while (inputLength - offSet > 0) {
                if (inputLength - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(inputArray, offSet, MAX_ENCRYPT_BLOCK);
                    offSet += MAX_ENCRYPT_BLOCK;
                } else {
                    cache = cipher.doFinal(inputArray, offSet, inputLength - offSet);
                    offSet = inputLength;
                }
                resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + cache.length);
                System.arraycopy(cache, 0, resultBytes, resultBytes.length - cache.length, cache.length);
            }
//          Writing encoded content to a stream output
            for (byte b : resultBytes) {
                outputStream.write(b);
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    //  AES key decryption
    public static void decryptFile(String path, String path2, String privateKey) throws IOException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException {
        File file = new File(path);
        File file2 = new File(path2);
        file2.getParentFile().mkdirs();
        file.getParentFile().mkdirs();

        try (
                FileOutputStream outputStream = new FileOutputStream(file2);
        ) {
//          Initializing the encryption method
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));

            byte[] inputFileRead = Files.readAllBytes(file.toPath());
            byte[] inputArray = Base64.getMimeDecoder().decode(inputFileRead);
            int inputLength = inputArray.length;
            int MAX_DECRYPT_BLOCK = 128;
            int offSet = 0;
            byte[] resultBytes = {};
            byte[] cache = {};
//          Content decryption block by block
            while (inputLength - offSet > 0) {
                if (inputLength - offSet > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(inputArray, offSet, MAX_DECRYPT_BLOCK);
                    offSet += MAX_DECRYPT_BLOCK;
                } else {
                    cache = cipher.doFinal(inputArray, offSet, inputLength - offSet);
                    offSet = inputLength;
                }
                resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + cache.length);
                System.arraycopy(cache, 0, resultBytes, resultBytes.length - cache.length, cache.length);
            }
//          Writing decoded content to a stream output
            for (byte b : resultBytes) {
                outputStream.write(b);
            }
            decryptAESFile("JS_encoded/content.txt", "Decoded/content.txt", resultBytes);
        }
    }

    //  Content decryption with aes key
    public static void decryptAESFile(String path, String path2, byte[] aesKey) throws IOException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException {
        File file = new File(path);
        File file2 = new File(path2);
        file2.getParentFile().mkdirs();
        file.getParentFile().mkdirs();

        try (
                FileOutputStream outputStream = new FileOutputStream(file2);
        ) {
            String secret = new String(aesKey);

            byte[] inputArray = Files.readAllBytes(file.toPath());
            byte[] cipherData = Base64.getMimeDecoder().decode(inputArray);
            byte[] saltData = Arrays.copyOfRange(cipherData, 8, 16);

            MessageDigest md5 = MessageDigest.getInstance("MD5");
            final byte[][] keyAndIV = GenerateKeyAndIV(32, 16, 1, saltData, secret.getBytes(StandardCharsets.UTF_8), md5);
            SecretKeySpec key = new SecretKeySpec(keyAndIV[0], "AES");
            IvParameterSpec iv = new IvParameterSpec(keyAndIV[1]);

            byte[] encrypted = Arrays.copyOfRange(cipherData, 16, cipherData.length);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] decryptedData = cipher.doFinal(encrypted);
            String decryptedText = new String(decryptedData, StandardCharsets.UTF_8);

            for (byte b : decryptedText.getBytes()) {
                outputStream.write(b);
            }
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    //  Overrides OpenSSL key get function
    public static byte[][] GenerateKeyAndIV(int keyLength, int ivLength, int iterations, byte[] salt, byte[] password, MessageDigest md) {
        int digestLength = md.getDigestLength();
        int requiredLength = (keyLength + ivLength + digestLength - 1) / digestLength * digestLength;
        byte[] generatedData = new byte[requiredLength];
        int generatedLength = 0;

        try {
            md.reset();
//          Repeat process until sufficient data has been generated
            while (generatedLength < keyLength + ivLength) {

//              Digest data (last digest if available, password data, salt if available)
                if (generatedLength > 0)
                    md.update(generatedData, generatedLength - digestLength, digestLength);
                md.update(password);
                if (salt != null)
                    md.update(salt, 0, 8);
                md.digest(generatedData, generatedLength, digestLength);
//              Additional rounds
                for (int i = 1; i < iterations; i++) {
                    md.update(generatedData, generatedLength, digestLength);
                    md.digest(generatedData, generatedLength, digestLength);
                }
                generatedLength += digestLength;
            }

//          Copy key and IV into separate byte arrays
            byte[][] result = new byte[2][];
            result[0] = Arrays.copyOfRange(generatedData, 0, keyLength);
            if (ivLength > 0)
                result[1] = Arrays.copyOfRange(generatedData, keyLength, keyLength + ivLength);
            return result;
        } catch (DigestException e) {
            throw new RuntimeException(e);
        } finally {
//          Clean out temporary data
            Arrays.fill(generatedData, (byte) 0);
        }
    }

    //  Converting public key string according to x.509 certificate
    public static PublicKey getPublicKey(String base64PublicKey) {
        PublicKey publicKey = null;
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    //  Converting private key string according to PKCS8 certificate
    public static PrivateKey getPrivateKey(String base64PrivateKey) {
        PrivateKey privateKey = null;
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, InterruptedException {
        App keyPairGenerator = new App();
//      Writing keys to files
        keyPairGenerator.writeToFile("RSA/publicKey", Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded()));
        keyPairGenerator.writeToFile("RSA/privateKey", Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded()));
//      encryptFile("Files/cat.txt", "Encoded/cat.txt", Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded()));
        System.out.println(Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded()));
//      Artificial delay in program execution for loading encrypted content on JS
        Thread.sleep(50000);
//      Decoding content from JS
        decryptFile("JS_encoded/aes_key.txt", "Decoded/aes_key.txt", Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded()));
//      Outputting keys to the console
        System.out.println(Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded()));
        System.out.println(Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded()));
    }
}