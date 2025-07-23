package com.voting.crypto;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/**
 * Cryptographic utilities for the secure voting protocol
 * Provides RSA encryption, digital signatures, and hashing functionality
 * Uses standard Java Cryptography Architecture (JCA)
 */
public class CryptoUtils {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final int KEY_SIZE = 2048;

    /**
     * Generate RSA key pair for voter
     * 
     * @return KeyPair containing public and private keys
     * @throws NoSuchAlgorithmException if RSA algorithm is not available
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Convert public key to Base64 encoded string
     * 
     * @param publicKey the public key to encode
     * @return Base64 encoded public key string
     */
    public static String encodePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Convert private key to Base64 encoded string
     * 
     * @param privateKey the private key to encode
     * @return Base64 encoded private key string
     */
    public static String encodePrivateKey(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    /**
     * Decode Base64 string to public key
     * 
     * @param encodedKey Base64 encoded public key
     * @return PublicKey object
     * @throws Exception if decoding fails
     */
    public static PublicKey decodePublicKey(String encodedKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePublic(spec);
    }

    /**
     * Decode Base64 string to private key
     * 
     * @param encodedKey Base64 encoded private key
     * @return PrivateKey object
     * @throws Exception if decoding fails
     */
    public static PrivateKey decodePrivateKey(String encodedKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }

    /**
     * Encrypt message using RSA public key
     * 
     * @param message   the message to encrypt
     * @param publicKey the public key for encryption
     * @return Base64 encoded encrypted message
     * @throws Exception if encryption fails
     */
    public static String rsaEncrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypt message using RSA private key
     * 
     * @param encryptedMessage Base64 encoded encrypted message
     * @param privateKey       the private key for decryption
     * @return decrypted message
     * @throws Exception if decryption fails
     */
    public static String rsaDecrypt(String encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Create digital signature for message
     * 
     * @param message    the message to sign
     * @param privateKey the private key for signing
     * @return Base64 encoded signature
     * @throws Exception if signing fails
     */
    public static String signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    /**
     * Verify digital signature
     * 
     * @param message         the original message
     * @param signatureString Base64 encoded signature
     * @param publicKey       the public key for verification
     * @return true if signature is valid, false otherwise
     */
    public static boolean verifySignature(String message, String signatureString, PublicKey publicKey) {
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(message.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = Base64.getDecoder().decode(signatureString);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            System.err.println("Signature verification failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Generate SHA-256 hash of input string
     * 
     * @param input the string to hash
     * @return hexadecimal hash string
     * @throws NoSuchAlgorithmException if SHA-256 is not available
     */
    public static String sha256Hash(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Generate secure random token
     * 
     * @param length the length of the token in bytes
     * @return hexadecimal token string
     */
    public static String generateSecureToken(int length) {
        SecureRandom random = new SecureRandom();
        byte[] tokenBytes = new byte[length];
        random.nextBytes(tokenBytes);

        StringBuilder hexString = new StringBuilder();
        for (byte b : tokenBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase();
    }

    /**
     * Generate unique voter ID
     * 
     * @return unique voter ID string
     */
    public static String generateVoterID() {
        return "VOTER_" + generateSecureToken(8);
    }

    /**
     * Generate unique ballot ID
     * 
     * @return unique ballot ID string
     */
    public static String generateBallotID() {
        return "BALLOT_" + generateSecureToken(8);
    }

    /**
     * Generate unique election ID
     * 
     * @return unique election ID string
     */
    public static String generateElectionID() {
        return "ELECTION_" + generateSecureToken(8);
    }

    /**
     * Test the cryptographic utilities
     */
    public static void main(String[] args) {
        try {
            System.out.println("Testing Cryptographic Utilities...");

            // Test key generation
            System.out.println("\n1. Generating RSA key pair...");
            KeyPair keyPair = generateRSAKeyPair();
            String publicKeyStr = encodePublicKey(keyPair.getPublic());
            String privateKeyStr = encodePrivateKey(keyPair.getPrivate());
            System.out.println("Keys generated successfully");

            // Test encryption/decryption
            System.out.println("\n2. Testing encryption/decryption...");
            String message = "This is a secret vote for Candidate A";
            String encrypted = rsaEncrypt(message, keyPair.getPublic());
            String decrypted = rsaDecrypt(encrypted, keyPair.getPrivate());
            System.out.println("Original: " + message);
            System.out.println("Decrypted: " + decrypted);
            System.out.println("Encryption/Decryption: " + (message.equals(decrypted) ? "PASSED" : "FAILED"));

            // Test digital signatures
            System.out.println("\n3. Testing digital signatures...");
            String signature = signMessage(message, keyPair.getPrivate());
            boolean isValid = verifySignature(message, signature, keyPair.getPublic());
            System.out.println("Digital Signature: " + (isValid ? "PASSED" : "FAILED"));

            // Test tampering detection
            System.out.println("\n4. Testing tampering detection...");
            String tamperedMessage = "This is a secret vote for Candidate B";
            boolean isTampered = verifySignature(tamperedMessage, signature, keyPair.getPublic());
            System.out.println("Tampering Detection: " + (!isTampered ? "PASSED" : "FAILED"));

            // Test hashing
            System.out.println("\n5. Testing SHA-256 hashing...");
            String hash1 = sha256Hash(message);
            String hash2 = sha256Hash(message);
            String hash3 = sha256Hash(tamperedMessage);
            System.out.println("Hash consistency: " + (hash1.equals(hash2) ? "PASSED" : "FAILED"));
            System.out.println("Hash uniqueness: " + (!hash1.equals(hash3) ? "PASSED" : "FAILED"));

            // Test token generation
            System.out.println("\n6. Testing secure token generation...");
            String token1 = generateSecureToken(16);
            String token2 = generateSecureToken(16);
            String voterID = generateVoterID();
            System.out.println("Token 1: " + token1);
            System.out.println("Token 2: " + token2);
            System.out.println("Voter ID: " + voterID);
            System.out.println("Token uniqueness: " + (!token1.equals(token2) ? "PASSED" : "FAILED"));

            System.out.println("\nAll cryptographic tests completed!");

        } catch (Exception e) {
            System.err.println("Error during testing: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
