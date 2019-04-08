package javaKMS;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.*;

import java.nio.ByteBuffer;
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
}
