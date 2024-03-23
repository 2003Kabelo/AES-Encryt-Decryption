import java.security.KeyStore.SecretKeyEntry;
import java.util.Base64;
import java.util.Scanner;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class AES {

    SecretKey key;
    private int key_size = 128;
    private int T_LEN = 128;
    private Cipher encryptionCipher;

    public void init() throws Exception {

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(key_size);
        key = generator.generateKey();

    }

    public String encrypt(String message) throws Exception{
        byte[] messageInbyte = message.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedByte = encryptionCipher.doFinal(messageInbyte);
        return encode(encryptedByte);
    }

    public String decrypt(String encryptmessage) throws Exception {

        byte[] messageInByte = decode(encryptmessage);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key ,spec);
        byte[] decryptedByte = decryptionCipher.doFinal(messageInByte);
        return new String(decryptedByte);

    }
    private String encode(byte[] data) {

        return Base64.getEncoder().encodeToString(data);
    }
    private byte[] decode(String data) {

        return Base64.getDecoder().decode(data);
    }
    public static void main(String[] args) throws Exception {

        try {
            Scanner sc = new Scanner(System.in);
            System.out.println("Enter the string to encrypted : ");
            String messString = sc.nextLine();
            AES aes = new AES();
            aes.init();
            String encryptedMessage = aes.encrypt(messString);
            String decryptedMessage = aes.decrypt(encryptedMessage);
            System.err.println("Encrypted message is : " + encryptedMessage);
            System.err.println("Decrypted message is : " + decryptedMessage);

        } catch (Exception e) {

            throw new Exception(e);

        }

    }

}
