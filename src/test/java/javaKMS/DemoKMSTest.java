package javaKMS;

import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.amazonaws.services.kms.model.KeyListEntry;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class DemoKMSTest {

    /* Notes...

        Not checking for deactivated keys
        Need to add permissions for encrypt/decrypt using key

        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "kms:Decrypt",
                        "kms:Encrypt"
                    ],
                    "Resource": "arn:aws:kms:REGION-GOES-HERE:ACCOUNT-ID-GOES-HERE:key/KEY-ID-GOES-HERE"
                }
            ]
        }
    */


    @Test
    public void showMeKeys() {
        List<KeyListEntry> keys = new DemoKMS().listKeys(10);
        Assert.assertFalse("Must have one or more keys", keys.isEmpty());
        keys.forEach((key) -> System.out.println(key.getKeyId()));
    }

    // Helper for the tests
    private String getKeyId() {
        return new DemoKMS().listKeys(1).get(0).getKeyId();
    }

    @Test
    public void canEncryptAndDecryptDataKey(){
        String keyId = getKeyId();
        ByteBuffer plainText = ByteBuffer.wrap(new byte[]{1,2,3,4,5,6,7,8,9,0});
        DemoKMS demoKMS = new DemoKMS();

        ByteBuffer cipherText = demoKMS.encryptTextWithKey(keyId, plainText);
        ByteBuffer decryptedText = demoKMS.decryptText(cipherText);

        Assert.assertArrayEquals(plainText.array(), decryptedText.array());
    }

    /*
    Requires policy

    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "kms:GenerateDataKey",
                "kms:GenerateDataKeyWithoutPlaintext"
            ],
            "Resource": "arn:aws:kms:REGION_GOES_HERE:ACCOUNT_GOES_HERE:key/KEY_GOES_HERE"
        }
    ]
}

     */
    @Test
    public void canEncryptDecryptWithDataKeys() {
        ByteBuffer plainText = ByteBuffer.wrap(new byte[]{1,2,3,4,5,6,7,8,9,0});
        DemoKMS demoKMS = new DemoKMS();

        GenerateDataKeyResult dataKey = demoKMS.generateDataKey(getKeyId());
        ByteBuffer cipherText = null;
        try {
            cipherText = demoKMS.encryptWithDataKey(plainText, dataKey.getPlaintext());
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        ByteBuffer decryptedText = null;
        try {
            decryptedText = demoKMS.decryptWithDataKey(cipherText, dataKey.getPlaintext());
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        Assert.assertArrayEquals(plainText.array(), decryptedText.array());
    }




}
