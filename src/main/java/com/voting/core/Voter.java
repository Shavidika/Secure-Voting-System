package com.voting.core;

import com.voting.crypto.CryptoUtils;
import com.voting.crypto.KeyPairManager;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents a voter in the secure electronic voting system
 * Handles voter registration, authentication, and vote casting
 */
public class Voter {

    private String voterID;
    private String name;
    private String studentID;
    private String email;
    private KeyPair keyPair;
    private String voteToken;
    private boolean isRegistered;
    private boolean hasVoted;
    private String registrationTimestamp;
    private String voteTimestamp;
    private KeyPairManager keyManager;

    /**
     * Constructor for new voter
     * 
     * @param name      full name of the voter
     * @param studentID student identification number
     * @param email     email address (optional)
     */
    public Voter(String name, String studentID, String email) {
        this.voterID = CryptoUtils.generateVoterID();
        this.name = name;
        this.studentID = studentID;
        this.email = email;
        this.isRegistered = false;
        this.hasVoted = false;
        this.keyManager = new KeyPairManager();

        System.out.println("👤 Created voter: " + name + " (ID: " + voterID + ")");
    }

    /**
     * Constructor for loading existing voter
     * 
     * @param voterID   existing voter ID
     * @param name      voter name
     * @param studentID student ID
     * @param email     email address
     */
    public Voter(String voterID, String name, String studentID, String email) {
        this.voterID = voterID;
        this.name = name;
        this.studentID = studentID;
        this.email = email;
        this.isRegistered = false;
        this.hasVoted = false;
        this.keyManager = new KeyPairManager();
    }

    /**
     * Register the voter and generate cryptographic keys
     * 
     * @return voter registration information for Election Authority
     * @throws Exception if registration fails
     */
    public Map<String, Object> register() throws Exception {
        System.out.println("📝 Registering voter: " + name);

        // Generate RSA key pair
        this.keyPair = keyManager.generateAndStoreKeyPair(voterID);
        this.isRegistered = true;
        this.registrationTimestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        // Create registration information for EA
        Map<String, Object> registrationInfo = new HashMap<>();
        registrationInfo.put("voterID", voterID);
        registrationInfo.put("name", name);
        registrationInfo.put("studentID", studentID);
        registrationInfo.put("email", email);
        registrationInfo.put("publicKey", CryptoUtils.encodePublicKey(keyPair.getPublic()));
        registrationInfo.put("registrationTimestamp", registrationTimestamp);

        System.out.println("✅ Voter registered successfully: " + voterID);
        return registrationInfo;
    }

    /**
     * Load voter's keys from storage
     * 
     * @throws Exception if key loading fails
     */
    public void loadKeys() throws Exception {
        if (keyManager.keyPairExists(voterID)) {
            this.keyPair = keyManager.loadKeyPair(voterID);
            System.out.println("🔑 Keys loaded for voter: " + voterID);
        } else {
            throw new Exception("No keys found for voter: " + voterID);
        }
    }

    /**
     * Receive and decrypt vote token from Election Authority
     * 
     * @param encryptedToken encrypted vote token from EA
     * @return true if token received successfully
     */
    public boolean receiveVoteToken(String encryptedToken) {
        try {
            if (keyPair == null) {
                loadKeys();
            }

            // Decrypt token using voter's private key
            this.voteToken = CryptoUtils.rsaDecrypt(encryptedToken, keyPair.getPrivate());
            System.out.println("🎫 Vote token received: " + voteToken.substring(0, 8) + "...");
            return true;
        } catch (Exception e) {
            System.err.println("❌ Error receiving vote token: " + e.getMessage());
            return false;
        }
    }

    /**
     * Cast a vote for the specified candidate
     * 
     * @param candidateChoice the candidate being voted for
     * @param eaPublicKey     Election Authority's public key for encryption
     * @return encrypted and signed ballot package
     * @throws Exception if vote casting fails
     */
    public Map<String, Object> castVote(String candidateChoice, PublicKey eaPublicKey) throws Exception {
        if (!isRegistered) {
            throw new IllegalStateException("Voter must be registered before casting vote");
        }

        if (voteToken == null) {
            throw new IllegalStateException("Voter must receive vote token before casting vote");
        }

        if (hasVoted) {
            throw new IllegalStateException("Voter has already cast their vote");
        }

        if (keyPair == null) {
            loadKeys();
        }

        System.out.println("🗳️ Casting vote for: " + candidateChoice);

        // Create ballot using Ballot class
        Ballot ballot = new Ballot(voteToken, candidateChoice, voterID);
        Map<String, Object> votePackage = ballot.createVotePackage(keyPair.getPrivate(), eaPublicKey);

        // Add voter's public key for signature verification
        votePackage.put("voterPublicKey", CryptoUtils.encodePublicKey(keyPair.getPublic()));

        // Mark voter as having voted
        this.hasVoted = true;
        this.voteTimestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        System.out.println("✅ Vote cast successfully!");
        System.out.println("   Ballot Hash: " + votePackage.get("ballotHash"));

        return votePackage;
    }

    /**
     * Verify that the voter's ballot was included in the election
     * 
     * @param ballotHash      hash of the voter's ballot
     * @param publishedHashes list of published ballot hashes
     * @return true if ballot was included
     */
    public boolean verifyVoteReceipt(String ballotHash, String[] publishedHashes) {
        for (String hash : publishedHashes) {
            if (hash.equals(ballotHash)) {
                System.out.println("✅ Vote verified: Ballot was included in election");
                return true;
            }
        }
        System.out.println("❌ Vote not found: Ballot was not included in election");
        return false;
    }

    /**
     * Get voter information (without sensitive data)
     * 
     * @param includeKeys whether to include key information
     * @return map containing voter information
     */
    public Map<String, Object> getVoterInfo(boolean includeKeys) {
        Map<String, Object> info = new HashMap<>();
        info.put("voterID", voterID);
        info.put("name", name);
        info.put("studentID", studentID);
        info.put("email", email);
        info.put("isRegistered", isRegistered);
        info.put("hasVoted", hasVoted);
        info.put("registrationTimestamp", registrationTimestamp);
        info.put("voteTimestamp", voteTimestamp);

        if (includeKeys) {
            info.put("hasKeyPair", keyPair != null);
            info.put("hasVoteToken", voteToken != null);
            if (keyPair != null) {
                info.put("publicKey", CryptoUtils.encodePublicKey(keyPair.getPublic()));
            }
        }

        return info;
    }

    /**
     * Create anonymous voter info for audit purposes
     * 
     * @return anonymized voter information
     */
    public Map<String, Object> getAnonymizedInfo() {
        Map<String, Object> info = new HashMap<>();
        try {
            info.put("voterIDHash", CryptoUtils.sha256Hash(voterID));
            info.put("studentIDHash", CryptoUtils.sha256Hash(studentID));
            info.put("isRegistered", isRegistered);
            info.put("hasVoted", hasVoted);
            info.put("registrationTimestamp", registrationTimestamp);
            info.put("voteTimestamp", voteTimestamp);
        } catch (Exception e) {
            System.err.println("Error creating anonymized info: " + e.getMessage());
        }
        return info;
    }

    // Getters and setters
    public String getVoterID() {
        return voterID;
    }

    public String getName() {
        return name;
    }

    public String getStudentID() {
        return studentID;
    }

    public String getEmail() {
        return email;
    }

    public boolean isRegistered() {
        return isRegistered;
    }

    public boolean hasVoted() {
        return hasVoted;
    }

    public String getRegistrationTimestamp() {
        return registrationTimestamp;
    }

    public String getVoteTimestamp() {
        return voteTimestamp;
    }

    public PublicKey getPublicKey() {
        return keyPair != null ? keyPair.getPublic() : null;
    }

    public void setRegistered(boolean registered) {
        this.isRegistered = registered;
    }

    public void setHasVoted(boolean hasVoted) {
        this.hasVoted = hasVoted;
    }

    public void setRegistrationTimestamp(String timestamp) {
        this.registrationTimestamp = timestamp;
    }

    public void setVoteTimestamp(String timestamp) {
        this.voteTimestamp = timestamp;
    }

    /**
     * Test the Voter class functionality
     */
    public static void main(String[] args) {
        try {
            System.out.println("👤 Testing Voter Class...");

            // Create a test voter
            System.out.println("\n1. Creating voter...");
            Voter voter = new Voter("Alice Johnson", "STU001", "alice@university.edu");
            System.out.println("Created voter: " + voter.getName() + " (ID: " + voter.getVoterID() + ")");

            // Register voter
            System.out.println("\n2. Registering voter...");
            Map<String, Object> registrationInfo = voter.register();
            System.out.println("Registration info keys: " + registrationInfo.keySet());

            // Simulate receiving vote token
            System.out.println("\n3. Simulating vote token reception...");
            // Generate EA keys for testing
            KeyPair eaKeyPair = CryptoUtils.generateRSAKeyPair();

            // Simulate EA encrypting token for voter
            String voteToken = CryptoUtils.generateSecureToken(16);
            String encryptedToken = CryptoUtils.rsaEncrypt(voteToken, voter.getPublicKey());

            // Voter receives token
            boolean tokenReceived = voter.receiveVoteToken(encryptedToken);
            System.out.println("Token reception: " + (tokenReceived ? "SUCCESS" : "FAILED"));

            // Cast vote
            System.out.println("\n4. Casting vote...");
            try {
                Map<String, Object> votePackage = voter.castVote("Candidate A", eaKeyPair.getPublic());
                System.out.println("Vote package keys: " + votePackage.keySet());
                System.out.println("Vote cast: SUCCESS");
            } catch (Exception e) {
                System.out.println("Vote cast: FAILED - " + e.getMessage());
            }

            // Test voter info
            System.out.println("\n5. Testing voter info...");
            Map<String, Object> voterInfo = voter.getVoterInfo(true);
            System.out.println("Voter info: " + voterInfo);

            Map<String, Object> anonymizedInfo = voter.getAnonymizedInfo();
            System.out.println("Anonymized info: " + anonymizedInfo);

            System.out.println("\n🎉 All voter tests completed!");

        } catch (Exception e) {
            System.err.println("❌ Error during testing: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
