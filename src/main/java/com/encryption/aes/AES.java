package com.encryption.aes;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.apache.commons.codec.binary.Base64;


public class AES {

    private static SecretKeySpec secretKeySpec;
    private static byte[] key;
    private static String encryptedString;
    private static String decryptedString;

    public static void setKey(String mKey) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        MessageDigest sha = null;
            key = mKey.getBytes("UTF-8");
            System.out.println(key.length);
            sha = MessageDigest.getInstance("SHA1");
            key = sha.digest();
            key = Arrays.copyOf(key, 16);
            System.out.println(key.length);
            System.out.println(new String(key, "UTF-8"));
            secretKeySpec = new SecretKeySpec(key, "AES");
    }

    public static String getEncryptedString() {
        return encryptedString;
    }

    public static void setEncryptedString(String encryptedString) {
        AES.encryptedString = encryptedString;
    }

    public static String getDecryptedString() {
        return decryptedString;
    }

    public static void setDecryptedString(String decryptedString) {
        AES.decryptedString = decryptedString;
    }

    public static void encrypt(String dataToEncrypt) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        setEncryptedString(new String(Base64.encodeBase64(cipher.doFinal(dataToEncrypt.getBytes()))));

//        setEncryptedString()encodeBase64String(cipher.doFinal(dataToEncrypt.getBytes("UTF-8"))));
    }

    public static void decrypt(String dataToDecrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        setDecryptedString(new String(cipher.doFinal(Base64.decodeBase64(dataToDecrypt.getBytes()))));

    }

    public static void main(String[] args) {
        final String strToEncrypt = "Danijax";
        final String strPssword = "encryptor key";
        try {
            AES.setKey(strPssword);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            AES.encrypt(strToEncrypt.trim());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        System.out.println("String to Encrypt: " + strToEncrypt);
        System.out.println("Encrypted: " + AES.getEncryptedString());

        final String strToDecrypt =  AES.getEncryptedString();
        try {
            AES.decrypt(strToDecrypt.trim());
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        System.out.println("String To Decrypt : " + strToDecrypt);
        System.out.println("Decrypted : " + AES.getDecryptedString());
    }
}
