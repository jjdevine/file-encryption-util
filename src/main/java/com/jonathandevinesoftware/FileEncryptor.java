package com.jonathandevinesoftware;

import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hello world!
 *
 */
public class FileEncryptor
{
    public static void main( String[] args ) throws Exception {

        if(args .length != 2) {
            System.out.println("2 args expected: [filename] [password]");
        }

        File f = new File(args[0]);
        String password = args[1];

        boolean encryptionMode = !args[0].endsWith(".encrypted");

        String outputFileName = encryptionMode ?
                args[0] + ".encrypted"
                : args[0].substring(0, args[0].lastIndexOf(".encrypted"));

        if(f == null || !f.exists()) {
            System.out.println("Not a valid file " + f);
            System.exit(-1);
        }

        System.out.println((encryptionMode ? "Encrypting" : "Decrypting")
                + " file " + f.getAbsolutePath());

        String algorithm = "AES/CBC/PKCS5Padding";

        SecretKey key = getKeyFromPassword(password, "salt123");

        if(encryptionMode) {
            encryptFile(algorithm, key, generateIv(), f, new File(outputFileName));
        }
        else {
            decryptFile(algorithm, key, generateIv(), f, new File(outputFileName));
        }

    }

    public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
                                   File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    }

    public static void decryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
                                   File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    }

    public static SecretKey getKeyFromPassword(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 128);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), "AES");
        return secret;
    }

    public static IvParameterSpec generateIv() {
        String bytes = "abcdefghijklmnop";
        return new IvParameterSpec(bytes.getBytes(StandardCharsets.UTF_8));
    }
}
