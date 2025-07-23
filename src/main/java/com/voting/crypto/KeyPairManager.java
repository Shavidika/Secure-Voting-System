package com.voting.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Manages RSA key pairs for voters and election authority
 * Handles key generation, storage, and retrieval
 */
public class KeyPairManager {

    private final String baseDirectory;
    private final Map<String, KeyPair> keyPairCache;

    /**
     * Constructor for KeyPairManager
     * 
     * @param baseDirectory base directory for storing key files
     */
    public KeyPairManager(String baseDirectory) {
        this.baseDirectory = baseDirectory;
        this.keyPairCache = new HashMap<>();
        createDirectoryIfNotExists();
    }

    /**
     * Default constructor using "data/keys" as base directory
     */
    public KeyPairManager() {
        this("data/keys");
    }

    /**
     * Create directory if it doesn't exist
     */
    private void createDirectoryIfNotExists() {
        try {
            Path path = Paths.get(baseDirectory);
            if (!Files.exists(path)) {
                Files.createDirectories(path);
                System.out.println("📁 Created directory: " + baseDirectory);
            }
        } catch (IOException e) {
            System.err.println("❌ Error creating directory: " + e.getMessage());
        }
    }

    /**
     * Generate and store key pair for an entity (voter or EA)
     * 
     * @param entityId unique identifier for the entity
     * @return generated KeyPair
     * @throws Exception if key generation or storage fails
     */
    public KeyPair generateAndStoreKeyPair(String entityId) throws Exception {
        System.out.println("🔑 Generating key pair for: " + entityId);

        // Generate new key pair
        KeyPair keyPair = CryptoUtils.generateRSAKeyPair();

        // Store keys to files
        storeKeyPair(entityId, keyPair);

        // Cache the key pair
        keyPairCache.put(entityId, keyPair);

        System.out.println("✅ Key pair generated and stored for: " + entityId);
        return keyPair;
    }

    /**
     * Store key pair to files
     * 
     * @param entityId unique identifier for the entity
     * @param keyPair  the key pair to store
     * @throws IOException if file operations fail
     */
    private void storeKeyPair(String entityId, KeyPair keyPair) throws IOException {
        // Store public key
        String publicKeyPath = baseDirectory + "/" + entityId + "_public.key";
        String encodedPublicKey = CryptoUtils.encodePublicKey(keyPair.getPublic());
        Files.write(Paths.get(publicKeyPath), encodedPublicKey.getBytes());

        // Store private key
        String privateKeyPath = baseDirectory + "/" + entityId + "_private.key";
        String encodedPrivateKey = CryptoUtils.encodePrivateKey(keyPair.getPrivate());
        Files.write(Paths.get(privateKeyPath), encodedPrivateKey.getBytes());

        System.out.println("   📄 Public key saved: " + publicKeyPath);
        System.out.println("   📄 Private key saved: " + privateKeyPath);
    }

    /**
     * Load key pair from files
     * 
     * @param entityId unique identifier for the entity
     * @return loaded KeyPair
     * @throws Exception if loading fails
     */
    public KeyPair loadKeyPair(String entityId) throws Exception {
        // Check cache first
        if (keyPairCache.containsKey(entityId)) {
            return keyPairCache.get(entityId);
        }

        System.out.println("🔑 Loading key pair for: " + entityId);

        // Load public key
        String publicKeyPath = baseDirectory + "/" + entityId + "_public.key";
        String encodedPublicKey = new String(Files.readAllBytes(Paths.get(publicKeyPath)));
        PublicKey publicKey = CryptoUtils.decodePublicKey(encodedPublicKey);

        // Load private key
        String privateKeyPath = baseDirectory + "/" + entityId + "_private.key";
        String encodedPrivateKey = new String(Files.readAllBytes(Paths.get(privateKeyPath)));
        PrivateKey privateKey = CryptoUtils.decodePrivateKey(encodedPrivateKey);

        // Create key pair
        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        // Cache the key pair
        keyPairCache.put(entityId, keyPair);

        System.out.println("✅ Key pair loaded for: " + entityId);
        return keyPair;
    }

    /**
     * Load only public key from file
     * 
     * @param entityId unique identifier for the entity
     * @return loaded PublicKey
     * @throws Exception if loading fails
     */
    public PublicKey loadPublicKey(String entityId) throws Exception {
        String publicKeyPath = baseDirectory + "/" + entityId + "_public.key";
        String encodedPublicKey = new String(Files.readAllBytes(Paths.get(publicKeyPath)));
        return CryptoUtils.decodePublicKey(encodedPublicKey);
    }

    /**
     * Check if key pair exists for entity
     * 
     * @param entityId unique identifier for the entity
     * @return true if both public and private key files exist
     */
    public boolean keyPairExists(String entityId) {
        String publicKeyPath = baseDirectory + "/" + entityId + "_public.key";
        String privateKeyPath = baseDirectory + "/" + entityId + "_private.key";
        return Files.exists(Paths.get(publicKeyPath)) && Files.exists(Paths.get(privateKeyPath));
    }

    /**
     * Get public key as encoded string
     * 
     * @param entityId unique identifier for the entity
     * @return Base64 encoded public key string
     * @throws Exception if key loading fails
     */
    public String getEncodedPublicKey(String entityId) throws Exception {
        PublicKey publicKey = loadPublicKey(entityId);
        return CryptoUtils.encodePublicKey(publicKey);
    }

    /**
     * Delete key pair files for entity
     * 
     * @param entityId unique identifier for the entity
     * @return true if deletion was successful
     */
    public boolean deleteKeyPair(String entityId) {
        try {
            String publicKeyPath = baseDirectory + "/" + entityId + "_public.key";
            String privateKeyPath = baseDirectory + "/" + entityId + "_private.key";

            boolean publicDeleted = Files.deleteIfExists(Paths.get(publicKeyPath));
            boolean privateDeleted = Files.deleteIfExists(Paths.get(privateKeyPath));

            // Remove from cache
            keyPairCache.remove(entityId);

            System.out.println("🗑️ Deleted key pair for: " + entityId);
            return publicDeleted && privateDeleted;
        } catch (IOException e) {
            System.err.println("❌ Error deleting key pair for " + entityId + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * List all entities that have key pairs
     * 
     * @return array of entity IDs
     */
    public String[] listEntitiesWithKeys() {
        try {
            return Files.list(Paths.get(baseDirectory))
                    .filter(path -> path.toString().endsWith("_public.key"))
                    .map(path -> {
                        String fileName = path.getFileName().toString();
                        return fileName.substring(0, fileName.lastIndexOf("_public.key"));
                    })
                    .toArray(String[]::new);
        } catch (IOException e) {
            System.err.println("❌ Error listing entities: " + e.getMessage());
            return new String[0];
        }
    }

    /**
     * Get key pair statistics
     * 
     * @return map containing statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        String[] entities = listEntitiesWithKeys();

        stats.put("total_entities", entities.length);
        stats.put("cached_key_pairs", keyPairCache.size());
        stats.put("base_directory", baseDirectory);
        stats.put("entities", entities);

        return stats;
    }

    /**
     * Test the KeyPairManager functionality
     */
    public static void main(String[] args) {
        try {
            System.out.println("🔑 Testing KeyPairManager...");

            KeyPairManager manager = new KeyPairManager("test_keys");

            // Test key generation and storage
            System.out.println("\n1. Testing key generation and storage...");
            String testEntityId = "TEST_VOTER_001";
            KeyPair keyPair = manager.generateAndStoreKeyPair(testEntityId);
            System.out.println("✅ Key generation: PASSED");

            // Test key loading
            System.out.println("\n2. Testing key loading...");
            KeyPair loadedKeyPair = manager.loadKeyPair(testEntityId);
            boolean keysMatch = keyPair.getPublic().equals(loadedKeyPair.getPublic()) &&
                    keyPair.getPrivate().equals(loadedKeyPair.getPrivate());
            System.out.println("✅ Key loading: " + (keysMatch ? "PASSED" : "FAILED"));

            // Test public key only loading
            System.out.println("\n3. Testing public key loading...");
            PublicKey publicKey = manager.loadPublicKey(testEntityId);
            boolean publicKeyMatches = keyPair.getPublic().equals(publicKey);
            System.out.println("✅ Public key loading: " + (publicKeyMatches ? "PASSED" : "FAILED"));

            // Test existence check
            System.out.println("\n4. Testing existence check...");
            boolean exists = manager.keyPairExists(testEntityId);
            boolean notExists = !manager.keyPairExists("NON_EXISTENT_ID");
            System.out.println("✅ Existence check: " + (exists && notExists ? "PASSED" : "FAILED"));

            // Test statistics
            System.out.println("\n5. Testing statistics...");
            Map<String, Object> stats = manager.getStatistics();
            System.out.println("Statistics: " + stats);

            // Test cleanup
            System.out.println("\n6. Testing cleanup...");
            boolean deleted = manager.deleteKeyPair(testEntityId);
            System.out.println("✅ Cleanup: " + (deleted ? "PASSED" : "FAILED"));

            System.out.println("\n🎉 All KeyPairManager tests completed!");

        } catch (Exception e) {
            System.err.println("❌ Error during testing: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
