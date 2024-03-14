package euceg.encryption.functions;

import java.io.StringReader;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import com.appiancorp.suiteapi.common.Name;
import com.appiancorp.suiteapi.content.ContentService;
import com.appiancorp.suiteapi.expression.annotations.Function;
import com.appiancorp.suiteapi.expression.annotations.Parameter;
import com.appiancorp.suiteapi.knowledge.DocumentDataType;

import euceg.encryption.EEHelper;

@EECategory
public class EEEncryption {

    /* Returns the string encoded in Base64 */
    @Function
    public String encodeStringToBase64(
            @Parameter @Name("text") String text) {

        /* Early exit */
        if (text == null) {
            return null;
        }

        /* Return the encoded string */
        return EEHelper.encodeToBase64String(text.getBytes());
    }

    /* Returns the text decoded from Base64 */
    @Function
    public String decodeBase64ToString(
            @Parameter @Name("base64text") String base64text) {

        /* Early exit */
        if (base64text == null) {
            return null;
        }

        /* Return the decoded text */
        return new String(EEHelper.decodeFromBase64String(base64text));
    }

    /* Returns the generated SHA-512 digest encoded in hex string */
    @Function
    public String computeSHA512(
            ContentService cs,
            @Parameter(required = false) @Name("documentId") @DocumentDataType Long documentId,
            @Parameter(required = false) @Name("text") String text) {

        /* Early exit */
        if (documentId == null && text == null) {
            return null;
        }

        try {
            /* Retrieve document or text bytes */
            byte[] content = (documentId == null) ? text.getBytes() : EEHelper.downloadDocumentBytes(cs, documentId);

            /* Compute digest */
            byte[] digest = EEHelper.computeSHA512(content);

            /* Return the generated digest encoded in hex string */
            return EEHelper.encodeToHexString(digest);
        } catch (Exception e) {
            EEHelper.logError(e.getMessage());
            return null;
        }
    }

    /* Returns the binary document encoded in Base64 */
    @Function
    public String binaryFileToBase64(
            ContentService cs,
            @Parameter @Name("documentId") @DocumentDataType Long documentId) {

        /* Early exit */
        if (documentId == null) {
            return null;
        }

        try {
            /* Retrieve document bytes */
            byte[] content = EEHelper.downloadDocumentBytes(cs, documentId);

            /* Return the document encoded in Base64 */
            return EEHelper.encodeToBase64String(content);
        } catch (Exception e) {
            EEHelper.logError(e.getMessage());
            return null;
        }
    }

    /* Returns the generated AES key encoded in Base64 */
    @Function
    public String generateAESKey(@Parameter @Name("numBytes") int numBytes) {
        try {
            /* Generate AES key */
            byte[] key = EEHelper.generateAESKey(numBytes);

            /* Return the encoded key in Base64 */
            return EEHelper.encodeToBase64String(key);
        } catch (Exception e) {
            EEHelper.logError(e.getMessage());
            return null;
        }
    }

    /* Returns the encrypted content encoded in Base64 */
    @Function
    public String encryptWithAESKey(
            ContentService cs,
            @Parameter(required = false) @Name("documentId") @DocumentDataType Long documentId,
            @Parameter(required = false) @Name("text") String text,
            @Parameter(required = false) @Name("base64Key") String base64Key) {

        /* Early exit */
        if (documentId == null && text == null) {
            return null;
        }

        try {
            /* Retrieve document or text bytes */
            byte[] content = (documentId == null) ? text.getBytes() : EEHelper.downloadDocumentBytes(cs, documentId);

            /* AES key */
            byte[] key = (base64Key == null) ? EEHelper.generateAESKey(32) : EEHelper.decodeFromBase64String(base64Key);

            /* Encrypt content with AES key */
            byte[] encryptedBytes = EEHelper.encryptWithAESKey(content, key);

            /* Return encrypted content encoded in Base64 */
            return EEHelper.encodeToBase64String(encryptedBytes);
        } catch (Exception e) {
            EEHelper.logError(e.getMessage());
            return null;
        }
    }

    /* Returns the decrypted content encoded in Base64 */
    @Function
    public String decryptWithAESKey(
            @Parameter @Name("base64Key") String base64Key,
            @Parameter @Name("content") String content) {

        /* Early exit */
        if (base64Key == null || content == null) {
            return null;
        }

        try {
            /* Decode the Base64-encoded content and key */
            byte[] keyBytes = EEHelper.decodeFromBase64String(base64Key);
            byte[] encryptedBytes = EEHelper.decodeFromBase64String(content);

            /* Initialize AES cipher for decryption */
            byte[] decryptedBytes = EEHelper.decryptWithAESKey(encryptedBytes, keyBytes);

            /* Returns the decrypted content encoded in Base64 */
            return EEHelper.encodeToBase64String(decryptedBytes);
        } catch (Exception e) {
            EEHelper.logError(e.getMessage());
            return null;
        }
    }

    /* Returns the encrypted content encoded in Base64 */
    @Function
    public String encryptWithPubKey(
            ContentService cs,
            @Parameter @Name("truststoreDocumentId") @DocumentDataType Long truststoreDocumentId,
            @Parameter @Name("alias") String alias,
            @Parameter @Name("password") String password,
            @Parameter @Name("content") String content) {

        /* Early exit */
        if (truststoreDocumentId == null || content == null || alias == null) {
            return null;
        }

        try {
            /* Public key */
            PublicKey pubKey = EEHelper.getPublicKey(cs, truststoreDocumentId, alias, password);

            /* Encrypt with public key */
            byte[] encryptedBytes = EEHelper.encryptWithPubKey(EEHelper.decodeFromBase64String(content), pubKey);

            /* Return the encrypted content encoded in Base64 */
            return EEHelper.encodeToBase64String(encryptedBytes);
        } catch (Exception e) {
            EEHelper.logError(e.getMessage());
            return null;
        }
    }

    /* Returns the decrypted content encoded in Base64 */
    @Function
    public String decryptWithPrivateKey(
            ContentService cs,
            @Parameter @Name("keystoreDocumentId") @DocumentDataType Long keystoreDocumentId,
            @Parameter @Name("alias") String alias,
            @Parameter @Name("password") String password,
            @Parameter @Name("passwordKey") String passwordKey,
            @Parameter @Name("content") String content) {

        /* Early exit */
        if (keystoreDocumentId == null || content == null || alias == null) {
            return null;
        }

        try {
            /* Private key */
            PrivateKey privateKey = EEHelper.getPrivateKey(cs, keystoreDocumentId, alias, password, password);

            /* Decrypt with private key */
            byte[] decryptedBytes = EEHelper.decryptWithPrivateKey(EEHelper.decodeFromBase64String(content),
                    privateKey);

            /* Returns the decrypted content encoded in Base64 */
            return EEHelper.encodeToBase64String(decryptedBytes);
        } catch (Exception e) {
            EEHelper.logError(e.getMessage());
            return null;
        }
    }

    /* Returns the AS4 payload encoded in Base64 */
    @Function
    public String generateAS4Payload(
            ContentService cs,
            @Parameter @Name("truststoreDocumentId") @DocumentDataType Long truststoreDocumentId,
            @Parameter @Name("alias") String alias,
            @Parameter @Name("password") String password,
            @Parameter(required = false) @Name("documentId") @DocumentDataType Long documentId,
            @Parameter(required = false) @Name("text") String text) {

        /* Early exit */
        if ((documentId == null && text == null) || truststoreDocumentId == null || alias == null) {
            return null;
        }

        try {
            /* Retrieve document or text bytes */
            byte[] content = (documentId == null) ? text.getBytes() : EEHelper.downloadDocumentBytes(cs, documentId);

            /* 1. Generate a random 256-bit key (32 bytes) */
            byte[] key = EEHelper.generateAESKey(32);

            /* 2. Compute checksum with hash SHA512 */
            String checksum = Hex.toHexString(EEHelper.computeSHA512(content));

            /* 3. Encrypt file with AES key */
            byte[] contentEncrypted = EEHelper.encryptWithAESKey(content, key);

            /* 4. Encrypt key with pub certificate */
            byte[] keyEncrypted = EEHelper.encryptWithPubKey(key,
                    EEHelper.getPublicKey(cs, truststoreDocumentId, alias, password));

            /* 5. Create the payload XML */
            String xmlPayload = String.format(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>%n" +
                            "<AS4Payload xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceSchemaLocation=\"as4Payload.xsd\">%n"
                            +
                            "    <Content>%s</Content>%n" +
                            "    <DocumentHash>%s</DocumentHash>%n" +
                            "    <Key>%s</Key>%n" +
                            "</AS4Payload>",
                    EEHelper.encodeToBase64String(contentEncrypted), checksum,
                    EEHelper.encodeToBase64String(keyEncrypted));

            /* Returns the AS4 payload encoded in Base64 */
            return EEHelper.encodeToBase64String(xmlPayload.getBytes());
        } catch (Exception e) {
            EEHelper.logError(e.getMessage());
            return null;
        }
    }

    /* Returns the decrypted AS4 payload */
    @Function
    public String decryptAS4Payload(
            ContentService cs,
            @Parameter @Name("keystoreDocumentId") @DocumentDataType Long keystoreDocumentId,
            @Parameter @Name("alias") String alias,
            @Parameter @Name("password") String password,
            @Parameter @Name("passwordKey") String passwordKey,
            @Parameter @Name("response") String response) {

        /* Early exit */
        if (response == null) {
            return null;
        }

        try {
            /* Decode the Base64-encoded content */
            String as4Payload = new String(EEHelper.decodeFromBase64String(response));

            /* Extract values */
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(as4Payload)));
            String content = doc.getElementsByTagName("Content").item(0).getTextContent();
            String key = doc.getElementsByTagName("Key").item(0).getTextContent();

            /* Private key */
            PrivateKey privateKey = EEHelper.getPrivateKey(cs, keystoreDocumentId, alias, password, password);

            /* Decrypt with private key */
            byte[] decryptedAESKey = EEHelper.decryptWithPrivateKey(EEHelper.decodeFromBase64String(key), privateKey);

            /* Decode the Base64-encoded content and key */
            byte[] encryptedBytes = EEHelper.decodeFromBase64String(content);

            /* Initialize AES cipher for decryption */
            byte[] decryptedBytes = EEHelper.decryptWithAESKey(encryptedBytes, decryptedAESKey);

            /* Returns the decrypted content encoded in Base64 */
            return new String(decryptedBytes);
        } catch (Exception e) {
            EEHelper.logError(e.getMessage());
            return null;
        }
    }
}
