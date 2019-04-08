package javaKMS;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.List;

public class DemoKMS {

    private AWSKMS kmsClient = AWSKMSClientBuilder.defaultClient();

    public DemoKMS() {

    }


    public List<KeyListEntry> listKeys(int limit){
        ListKeysRequest req = new ListKeysRequest().withLimit(limit);
        return kmsClient.listKeys(req).getKeys();
    }

    public ByteBuffer encryptTextWithKey(String keyId, ByteBuffer plainText) {
        EncryptRequest req = new EncryptRequest().withKeyId(keyId).withPlaintext(plainText);
        return kmsClient.encrypt(req).getCiphertextBlob();
    }

    public ByteBuffer decryptText(ByteBuffer cipherText) {
        DecryptRequest req = new DecryptRequest().withCiphertextBlob(cipherText);
        return kmsClient.decrypt(req).getPlaintext();
    }

    public GenerateDataKeyResult generateDataKey(String keyId) {
        GenerateDataKeyRequest dataKeyRequest = new GenerateDataKeyRequest();
        dataKeyRequest.setKeyId(keyId);
        dataKeyRequest.setKeySpec("AES_256");

        return kmsClient.generateDataKey(dataKeyRequest);
    }

    public ByteBuffer encryptWithDataKey(ByteBuffer input, ByteBuffer plaintextDataKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        SecretKeySpec secretKey = new SecretKeySpec(plaintextDataKey.array(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
        return ByteBuffer.wrap(cipher.doFinal(input.array()));
    }

    public ByteBuffer decryptWithDataKey(ByteBuffer cipherText, ByteBuffer plaintextDataKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        SecretKeySpec secretKey = new SecretKeySpec(plaintextDataKey.array(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
        return ByteBuffer.wrap(cipher.doFinal(cipherText.array()));
    }
}
