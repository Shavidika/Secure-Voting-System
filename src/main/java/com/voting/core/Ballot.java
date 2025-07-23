package com.voting.core;

import com.voting.crypto.CryptoUtils;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents an electronic ballot in the voting system
 * Handles ballot creation, encryption, signing, and verification
 */
public class Ballot {

    private String ballotID;
    private String voteToken;
    private String candidateChoice;
    private String voterID;
    private String creationTimestamp;
    private Map<String, Object> ballotData;
    private String ballotJSON;
    private String ballotHash;
    private String voterSignature;
    private String encryptedBallot;

    /**
     * Constructor for creating a new ballot
     * 
     * @param voteToken       unique vote token from EA
     * @param candidateChoice the candidate being voted for
     * @param voterID         the voter's ID (for internal tracking, not included in
     *                        final ballot)
     */
    public Ballot(String voteToken, String candidateChoice, String voterID) {
        this.ballotID = CryptoUtils.generateBallotID();
        this.voteToken = voteToken;
        this.candidateChoice = candidateChoice;
        this.voterID = voterID;
        this.creationTimestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        // Create ballot data structure
        createBallotData();

        System.out.println("🗳️ Ballot created for candidate: " + candidateChoice);
        System.out.println("   Ballot ID: " + ballotID);
        System.out.println("   Ballot Hash: " + ballotHash.substring(0, 16) + "...");
    }

    /**
     * Create the ballot data structure and hash
     */
    private void createBallotData() {
        try {
            this.ballotData = new HashMap<>();
            ballotData.put("ballotID", ballotID);
            ballotData.put("voteToken", voteToken);
            ballotData.put("candidate", candidateChoice);
            ballotData.put("timestamp", creationTimestamp);
            ballotData.put("ballotVersion", "1.0");

            // Convert to JSON string for hashing and signing
            this.ballotJSON = mapToJSON(ballotData);

            // Generate ballot hash
            this.ballotHash = CryptoUtils.sha256Hash(ballotJSON);

        } catch (Exception e) {
            System.err.println("❌ Error creating ballot data: " + e.getMessage());
            throw new RuntimeException("Failed to create ballot data", e);
        }
    }

    /**
     * Sign the ballot with voter's private key for integrity
     * 
     * @param voterPrivateKey voter's private key for signing
     * @return digital signature of the ballot
     * @throws Exception if signing fails
     */
    public String signBallot(PrivateKey voterPrivateKey) throws Exception {
        System.out.println("✍️ Signing ballot with voter's private key...");

        this.voterSignature = CryptoUtils.signMessage(ballotJSON, voterPrivateKey);
        System.out.println("✅ Ballot signed successfully");
        return voterSignature;
    }

    /**
     * Encrypt the ballot with EA's public key for confidentiality
     * 
     * @param eaPublicKey EA's public key for encryption
     * @return encrypted ballot
     * @throws Exception if encryption fails
     */
    public String encryptBallot(PublicKey eaPublicKey) throws Exception {
        System.out.println("🔐 Encrypting ballot with EA's public key...");

        this.encryptedBallot = CryptoUtils.rsaEncrypt(ballotJSON, eaPublicKey);
        System.out.println("✅ Ballot encrypted successfully");
        return encryptedBallot;
    }

    /**
     * Create the complete vote package for submission
     * 
     * @param voterPrivateKey voter's private key for signing
     * @param eaPublicKey     EA's public key for encryption
     * @return complete vote package ready for submission
     * @throws Exception if package creation fails
     */
    public Map<String, Object> createVotePackage(PrivateKey voterPrivateKey, PublicKey eaPublicKey) throws Exception {
        System.out.println("📦 Creating vote package...");

        // Sign the ballot
        if (voterSignature == null) {
            signBallot(voterPrivateKey);
        }

        // Encrypt the ballot
        if (encryptedBallot == null) {
            encryptBallot(eaPublicKey);
        }

        // Create the vote package
        Map<String, Object> votePackage = new HashMap<>();
        votePackage.put("ballotID", ballotID);
        votePackage.put("encryptedBallot", encryptedBallot);
        votePackage.put("voterSignature", voterSignature);
        votePackage.put("ballotHash", ballotHash);
        votePackage.put("submissionTimestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        votePackage.put("packageVersion", "1.0");

        // Add package integrity hash
        Map<String, Object> packageData = new HashMap<>();
        packageData.put("ballotID", ballotID);
        packageData.put("encryptedBallot", encryptedBallot);
        packageData.put("voterSignature", voterSignature);
        packageData.put("ballotHash", ballotHash);

        String packageJSON = mapToJSON(packageData);
        String packageHash = CryptoUtils.sha256Hash(packageJSON);
        votePackage.put("packageHash", packageHash);

        System.out.println("✅ Vote package created successfully");
        System.out.println("   Package Hash: " + packageHash.substring(0, 16) + "...");

        return votePackage;
    }

    /**
     * Verify the integrity of the ballot using the voter's signature
     * 
     * @param voterPublicKey voter's public key for verification
     * @return true if ballot integrity is verified
     */
    public boolean verifyBallotIntegrity(PublicKey voterPublicKey) {
        System.out.println("🔍 Verifying ballot integrity...");

        if (voterSignature == null) {
            System.out.println("❌ No signature found for verification");
            return false;
        }

        boolean isValid = CryptoUtils.verifySignature(ballotJSON, voterSignature, voterPublicKey);

        if (isValid) {
            System.out.println("✅ Ballot integrity verified");
        } else {
            System.out.println("❌ Ballot integrity verification failed");
        }

        return isValid;
    }

    /**
     * Decrypt the ballot using EA's private key (for EA use only)
     * 
     * @param eaPrivateKey EA's private key for decryption
     * @return decrypted ballot data
     * @throws Exception if decryption fails
     */
    public Map<String, Object> decryptBallot(PrivateKey eaPrivateKey) throws Exception {
        System.out.println("🔓 Decrypting ballot (EA operation)...");

        if (encryptedBallot == null) {
            throw new IllegalStateException("No encrypted ballot found");
        }

        String decryptedJSON = CryptoUtils.rsaDecrypt(encryptedBallot, eaPrivateKey);
        Map<String, Object> decryptedData = jsonToMap(decryptedJSON);

        System.out.println("✅ Ballot decrypted successfully");
        System.out.println("   Candidate: " + decryptedData.get("candidate"));

        return decryptedData;
    }

    /**
     * Get a summary of the ballot (without sensitive data)
     * 
     * @return ballot summary
     */
    public Map<String, Object> getBallotSummary() {
        Map<String, Object> summary = new HashMap<>();
        summary.put("ballotID", ballotID);
        summary.put("ballotHash", ballotHash);
        summary.put("creationTimestamp", creationTimestamp);
        summary.put("hasSignature", voterSignature != null);
        summary.put("hasEncryption", encryptedBallot != null);
        return summary;
    }

    /**
     * Create an anonymized version of the ballot for audit trails
     * 
     * @return anonymized ballot information
     */
    public Map<String, Object> anonymizeBallot() {
        Map<String, Object> anonymized = new HashMap<>();
        anonymized.put("ballotHash", ballotHash);
        anonymized.put("candidate", candidateChoice);
        anonymized.put("timestamp", creationTimestamp);
        anonymized.put("ballotVersion", ballotData.get("ballotVersion"));
        return anonymized;
    }

    /**
     * Verify the integrity of a complete vote package
     * 
     * @param votePackage vote package to verify
     * @return true if package integrity is verified
     */
    public static boolean verifyVotePackageIntegrity(Map<String, Object> votePackage) {
        System.out.println("🔍 Verifying vote package integrity...");

        // Check required fields
        String[] requiredFields = { "ballotID", "encryptedBallot", "voterSignature", "ballotHash", "packageHash" };
        for (String field : requiredFields) {
            if (!votePackage.containsKey(field)) {
                System.out.println("❌ Missing required field: " + field);
                return false;
            }
        }

        try {
            // Verify package hash
            Map<String, Object> packageData = new HashMap<>();
            packageData.put("ballotID", votePackage.get("ballotID"));
            packageData.put("encryptedBallot", votePackage.get("encryptedBallot"));
            packageData.put("voterSignature", votePackage.get("voterSignature"));
            packageData.put("ballotHash", votePackage.get("ballotHash"));

            String packageJSON = mapToJSON(packageData);
            String expectedHash = CryptoUtils.sha256Hash(packageJSON);
            String actualHash = (String) votePackage.get("packageHash");

            if (!expectedHash.equals(actualHash)) {
                System.out.println("❌ Package hash verification failed");
                return false;
            }

            System.out.println("✅ Vote package integrity verified");
            return true;
        } catch (Exception e) {
            System.out.println("❌ Error verifying package integrity: " + e.getMessage());
            return false;
        }
    }

    /**
     * Create a receipt for the voter after ballot submission
     * 
     * @param votePackage submitted vote package
     * @return voter receipt
     */
    public static Map<String, Object> createBallotReceipt(Map<String, Object> votePackage) {
        Map<String, Object> receipt = new HashMap<>();
        receipt.put("ballotID", votePackage.get("ballotID"));
        receipt.put("ballotHash", votePackage.get("ballotHash"));
        receipt.put("packageHash", votePackage.get("packageHash"));
        receipt.put("submissionTimestamp", votePackage.get("submissionTimestamp"));
        receipt.put("receiptMessage", "Your vote has been recorded. Keep this receipt for verification.");
        return receipt;
    }

    /**
     * Simple JSON conversion utility (basic implementation)
     * 
     * @param map map to convert to JSON
     * @return JSON string
     */
    private static String mapToJSON(Map<String, Object> map) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first)
                json.append(",");
            json.append("\"").append(entry.getKey()).append("\":\"").append(entry.getValue()).append("\"");
            first = false;
        }
        json.append("}");
        return json.toString();
    }

    /**
     * Simple JSON parsing utility (basic implementation)
     * 
     * @param json JSON string to parse
     * @return map representation
     */
    private static Map<String, Object> jsonToMap(String json) {
        Map<String, Object> map = new HashMap<>();
        // Simple JSON parsing - in production, use a proper JSON library
        String content = json.substring(1, json.length() - 1); // Remove braces
        String[] pairs = content.split(",");
        for (String pair : pairs) {
            String[] keyValue = pair.split(":");
            String key = keyValue[0].trim().replaceAll("\"", "");
            String value = keyValue[1].trim().replaceAll("\"", "");
            map.put(key, value);
        }
        return map;
    }

    // Getters
    public String getBallotID() {
        return ballotID;
    }

    public String getVoteToken() {
        return voteToken;
    }

    public String getCandidateChoice() {
        return candidateChoice;
    }

    public String getBallotHash() {
        return ballotHash;
    }

    public String getVoterSignature() {
        return voterSignature;
    }

    public String getEncryptedBallot() {
        return encryptedBallot;
    }

    public String getCreationTimestamp() {
        return creationTimestamp;
    }

    /**
     * Test the Ballot class functionality
     */
    public static void main(String[] args) {
        try {
            System.out.println("🗳️ Testing Ballot Class...");

            // Generate test keys
            System.out.println("\n1. Generating test keys...");
            KeyPair voterKeyPair = CryptoUtils.generateRSAKeyPair();
            KeyPair eaKeyPair = CryptoUtils.generateRSAKeyPair();

            // Create test ballot
            System.out.println("\n2. Creating test ballot...");
            String voteToken = CryptoUtils.generateSecureToken(16);
            Ballot ballot = new Ballot(voteToken, "Candidate A", "VOTER_TEST_001");

            // Test ballot signing
            System.out.println("\n3. Testing ballot signing...");
            String signature = ballot.signBallot(voterKeyPair.getPrivate());
            System.out.println("Signature created: " + signature.substring(0, 32) + "...");

            // Test ballot encryption
            System.out.println("\n4. Testing ballot encryption...");
            String encrypted = ballot.encryptBallot(eaKeyPair.getPublic());
            System.out.println("Encryption successful: " + encrypted.length() + " characters");

            // Test vote package creation
            System.out.println("\n5. Testing vote package creation...");
            Map<String, Object> votePackage = ballot.createVotePackage(voterKeyPair.getPrivate(),
                    eaKeyPair.getPublic());
            System.out.println("Vote package keys: " + votePackage.keySet());

            // Test ballot integrity verification
            System.out.println("\n6. Testing ballot integrity verification...");
            boolean integrityValid = ballot.verifyBallotIntegrity(voterKeyPair.getPublic());
            System.out.println("Integrity verification: " + (integrityValid ? "PASSED" : "FAILED"));

            // Test ballot decryption (EA operation)
            System.out.println("\n7. Testing ballot decryption...");
            Map<String, Object> decryptedData = ballot.decryptBallot(eaKeyPair.getPrivate());
            if (decryptedData != null) {
                System.out.println("Decrypted candidate: " + decryptedData.get("candidate"));
                System.out.println("Decryption: PASSED");
            } else {
                System.out.println("Decryption: FAILED");
            }

            // Test vote package integrity
            System.out.println("\n8. Testing vote package integrity...");
            boolean packageIntegrity = Ballot.verifyVotePackageIntegrity(votePackage);
            System.out.println("Package integrity: " + (packageIntegrity ? "PASSED" : "FAILED"));

            // Test ballot receipt
            System.out.println("\n9. Testing ballot receipt...");
            Map<String, Object> receipt = Ballot.createBallotReceipt(votePackage);
            System.out.println("Receipt created with keys: " + receipt.keySet());

            System.out.println("\n🎉 All ballot tests completed!");

        } catch (Exception e) {
            System.err.println("❌ Error during testing: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
