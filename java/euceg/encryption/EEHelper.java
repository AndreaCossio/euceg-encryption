package euceg.encryption;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import com.appiancorp.suiteapi.content.ContentConstants;
import com.appiancorp.suiteapi.content.ContentService;

import euceg.encryption.functions.EEEncryption;

public class EEHelper {
    /* Logger */
    private static final Logger LOG = Logger.getLogger(EEEncryption.class);

    /* Encode byte array to Base64 string */
    public static final String encodeToBase64String(byte[] data) {
        return Base64.toBase64String(data);
    }

    /* Decode Base64 string to byte array */
    public static final byte[] decodeFromBase64String(String base64String) {
        return Base64.decode(base64String);
    }

    /* Encode byte array to Hex string */
    public static final String encodeToHexString(byte[] data) {
        return Hex.toHexString(data);
    }

    /* AES Key */
    public static final byte[] generateAESKey(int numBytes) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(8 * numBytes);
        return keyGen.generateKey().getEncoded();
    }

    /* SHA-512 */
    public static final byte[] computeSHA512(byte[] data) throws Exception {
        SHA512Digest digest = new SHA512Digest();
        digest.update(data, 0, data.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    /* AES cipher */
    public static final BufferedBlockCipher getAESBlockCipher(byte[] key, boolean forEncryption) {
        BufferedBlockCipher bufferedBlockCipher = new PaddedBufferedBlockCipher(
                CBCBlockCipher.newInstance(AESEngine.newInstance()));

        bufferedBlockCipher.init(
                forEncryption,
                new ParametersWithIV(
                        new KeyParameter(key),
                        new byte[bufferedBlockCipher.getBlockSize()]));

        return bufferedBlockCipher;
    }

    /* Encrypt with AES key */
    public static final byte[] encryptWithAESKey(byte[] data, byte[] key) throws Exception {
        BufferedBlockCipher cipher = EEHelper.getAESBlockCipher(key, true);
        CipherInputStream cis = new CipherInputStream(new ByteArrayInputStream(data), cipher);
        byte[] encryptedBytes = IOUtils.toByteArray(cis);
        cis.close();
        return encryptedBytes;
    }

    /* Decrypt with AES key */
    public static final byte[] decryptWithAESKey(byte[] data, byte[] key) throws Exception {
        BufferedBlockCipher cipher = EEHelper.getAESBlockCipher(key, false);
        CipherInputStream cis = new CipherInputStream(new ByteArrayInputStream(data), cipher);
        byte[] decryptedBytes = IOUtils.toByteArray(cis);
        cis.close();
        return decryptedBytes;
    }

    /* Get public key from truststore */
    public static final PublicKey getPublicKey(ContentService cs, Long truststoreDocumentId, String alias,
            String password) throws Exception {
        try (InputStream truststore = EEHelper.downloadDocument(cs, truststoreDocumentId)) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(truststore, password.toCharArray());
            return ks.getCertificate(alias).getPublicKey();
        }
    }

    /* Encrypt with Pub key */
    public static final byte[] encryptWithPubKey(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data);
        return encryptedBytes;
    }

    /* Get private key from keystore */
    public static final PrivateKey getPrivateKey(ContentService cs, Long keystoreDocumentId, String alias,
            String password, String keyPassword) throws Exception {
        try (InputStream keystore = EEHelper.downloadDocument(cs, keystoreDocumentId)) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(keystore, password.toCharArray());
            Key key = ks.getKey(alias, keyPassword.toCharArray());
            if (!(key instanceof PrivateKey)) {
                throw new IllegalStateException("No private key found in the keystore under alias " + alias);
            }
            return (PrivateKey) key;
        }
    }

    /* Decrypt with Private key */
    public static final byte[] decryptWithPrivateKey(byte[] data, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(data);
        return decryptedBytes;
    }

    /* Log */
    public static final void logError(String message) {
        LOG.error(message);
    }

    /* Download lst version of appian document */
    public static final InputStream downloadDocument(ContentService cs, Long documentId) throws Exception {
        return cs.download(documentId, ContentConstants.VERSION_CURRENT, false)[0].getInputStream();
    }

    /* Download lst version of appian document - bytes */
    public static final byte[] downloadDocumentBytes(ContentService cs, Long documentId) throws Exception {
        return IOUtils.toByteArray(downloadDocument(cs, documentId));
    }
}
