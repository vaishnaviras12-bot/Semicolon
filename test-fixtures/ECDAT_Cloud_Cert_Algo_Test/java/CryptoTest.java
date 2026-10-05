import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.Cipher;

class CryptoTest {
    void test() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);

        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(256);

        Signature sig = Signature.getInstance("SHA256withRSA");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Synthetic PQC references:
        String kem = "ML-KEM-768";
        String dsa = "ML-DSA-65";
    }
}