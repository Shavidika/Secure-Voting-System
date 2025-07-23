package com.voting.core;

import com.voting.crypto.CryptoUtils;
import com.voting.crypto.KeyPairManager;
import com.voting.security.TokenManager;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Election Authority (EA) for Secure Electronic Voting Protocol
 * Handles voter verification, token issuance, ballot collection, and tallying
 */
public class ElectionAuthority {

    private String electionID;
    private String electionName;
    private List<String> candidates;
    private KeyPair eaKeyPair;
    private KeyPairManager keyManager;
    private TokenManager tokenManager;

    // Election data
    private Map<String, Map<String, Object>> registeredVoters; // voterID -> voter_info
    private List<Map<String, Object>> receivedBallots; // List of encrypted ballots
    private List<Map<String, Object>> verifiedVotes; // List of verified votes
    private Map<String, Integer> voteCounts; // candidate -> count

    // Election status
    private boolean registrationOpen;
    private boolean votingOpen;
    private boolean electionComplete;
    private String createdTimestamp;

    /**
     * Constructor for ElectionAuthority
     * 
     * @param electionName name of the election
     * @param candidates   list of candidate names
     */
    public ElectionAuthority(String electionName, List<String> candidates) {
        this.electionID = CryptoUtils.generateElectionID();
        this.electionName = electionName;
        this.candidates = new ArrayList<>(candidates);
        this.keyManager = new KeyPairManager();
        this.tokenManager = new TokenManager(electionID);

        // Initialize collections
        this.registeredVoters = new HashMap<>();
        this.receivedBallots = new ArrayList<>();
        this.verifiedVotes = new ArrayList<>();
        this.voteCounts = new HashMap<>();

        // Initialize vote counts for all candidates
        for (String candidate : candidates) {
            voteCounts.put(candidate, 0);
        }

        // Election status
        this.registrationOpen = true;
        this.votingOpen = false;
        this.electionComplete = false;
        this.createdTimestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        // Generate EA's RSA key pair
        try {
            this.eaKeyPair = keyManager.generateAndStoreKeyPair(electionID);
        } catch (Exception e) {
            System.err.println("❌ Error generating EA key pair: " + e.getMessage());
            throw new RuntimeException("Failed to initialize Election Authority", e);
        }

        System.out.println("🏛️ Election Authority initialized");
        System.out.println("   Election: " + electionName);
        System.out.println("   EA ID: " + electionID);
        System.out.println("   Candidates: " + candidates);
    }

    /**
     * Add a candidate to the election
     * 
     * @param candidateName name of the candidate to add
     */
    public void addCandidate(String candidateName) {
        if (!candidates.contains(candidateName)) {
            candidates.add(candidateName);
            voteCounts.put(candidateName, 0);
            System.out.println("✅ Candidate added: " + candidateName);
        } else {
            System.out.println("⚠️ Candidate already exists: " + candidateName);
        }
    }

    /**
     * Register a voter with the Election Authority
     * 
     * @param voterRegistrationInfo voter registration information
     * @return true if registration successful
     */
    public boolean registerVoter(Map<String, Object> voterRegistrationInfo) {
        String voterID = (String) voterRegistrationInfo.get("voterID");
        String studentID = (String) voterRegistrationInfo.get("studentID");

        if (!registrationOpen) {
            System.out.println("❌ Registration closed for voter " + voterID);
            return false;
        }

        // Check for duplicate registrations
        if (registeredVoters.containsKey(voterID)) {
            System.out.println("❌ Voter already registered: " + voterID);
            return false;
        }

        // Check for duplicate student IDs
        for (Map<String, Object> existingVoter : registeredVoters.values()) {
            if (studentID.equals(existingVoter.get("studentID"))) {
                System.out.println("❌ Student ID already registered: " + studentID);
                return false;
            }
        }

        // Verify registration data integrity
        String[] requiredFields = { "voterID", "name", "studentID", "publicKey" };
        for (String field : requiredFields) {
            if (!voterRegistrationInfo.containsKey(field)) {
                System.out.println("❌ Missing required registration field: " + field);
                return false;
            }
        }

        // Store voter registration
        Map<String, Object> voterData = new HashMap<>(voterRegistrationInfo);
        voterData.put("eaVerificationTimestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        registeredVoters.put(voterID, voterData);

        System.out.println("✅ Voter registered: " + voterRegistrationInfo.get("name") + " (" + voterID + ")");
        return true;
    }

    /**
     * Close voter registration
     */
    public void closeRegistration() {
        registrationOpen = false;
        System.out.println("🔒 Voter registration closed. Total registered: " + registeredVoters.size());
    }

    /**
     * Issue encrypted vote tokens to all registered voters
     * 
     * @return map of voterID -> encrypted_token
     */
    public Map<String, String> issueVoteTokens() {
        if (registrationOpen) {
            System.out.println("⚠️ Cannot issue tokens while registration is open");
            return new HashMap<>();
        }

        System.out.println("🎫 Issuing vote tokens to registered voters...");
        Map<String, String> issuedTokens = new HashMap<>();

        for (String voterID : registeredVoters.keySet()) {
            try {
                Map<String, Object> voterInfo = registeredVoters.get(voterID);
                String publicKeyString = (String) voterInfo.get("publicKey");
                PublicKey voterPublicKey = CryptoUtils.decodePublicKey(publicKeyString);

                // Generate and store token using TokenManager
                String encryptedToken = tokenManager.generateAndIssueToken(voterID, voterPublicKey);
                issuedTokens.put(voterID, encryptedToken);

                System.out.println("   ✅ Token issued to " + voterInfo.get("name") + " (" + voterID + ")");
            } catch (Exception e) {
                System.err.println("   ❌ Error issuing token to " + voterID + ": " + e.getMessage());
            }
        }

        System.out.println("🎫 Total tokens issued: " + issuedTokens.size());
        return issuedTokens;
    }

    /**
     * Open the voting process
     * 
     * @return true if voting opened successfully
     */
    public boolean openVoting() {
        if (registrationOpen) {
            System.out.println("❌ Cannot open voting while registration is open");
            return false;
        }

        if (tokenManager.getTotalIssuedTokens() == 0) {
            System.out.println("❌ Cannot open voting before issuing tokens");
            return false;
        }

        votingOpen = true;
        System.out.println("🗳️ Voting is now open!");
        return true;
    }

    /**
     * Receive and initially validate a ballot
     * 
     * @param votePackage encrypted vote package from voter
     * @return true if ballot accepted
     */
    public boolean receiveBallot(Map<String, Object> votePackage) {
        if (!votingOpen) {
            System.out.println("❌ Voting is not open");
            return false;
        }

        if (electionComplete) {
            System.out.println("❌ Election has ended");
            return false;
        }

        // Validate vote package structure
        String[] requiredFields = { "ballotID", "encryptedBallot", "voterSignature", "ballotHash" };
        for (String field : requiredFields) {
            if (!votePackage.containsKey(field)) {
                System.out.println("❌ Invalid vote package structure: missing " + field);
                return false;
            }
        }

        // Check for duplicate ballot hash (prevent double voting)
        String ballotHash = (String) votePackage.get("ballotHash");
        for (Map<String, Object> existingBallot : receivedBallots) {
            if (ballotHash.equals(existingBallot.get("ballotHash"))) {
                System.out.println("❌ Duplicate ballot detected: " + ballotHash.substring(0, 16) + "...");
                return false;
            }
        }

        // Verify vote package integrity
        if (!Ballot.verifyVotePackageIntegrity(votePackage)) {
            System.out.println("❌ Vote package integrity check failed");
            return false;
        }

        // Add reception timestamp
        Map<String, Object> ballotRecord = new HashMap<>(votePackage);
        ballotRecord.put("receivedTimestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

        // Store the ballot
        receivedBallots.add(ballotRecord);
        System.out.println(
                "✅ Ballot received: " + ballotHash.substring(0, 16) + "... (Total: " + receivedBallots.size() + ")");

        return true;
    }

    /**
     * Close the voting process
     */
    public void closeVoting() {
        votingOpen = false;
        System.out.println("🔒 Voting closed. Total ballots received: " + receivedBallots.size());
    }

    /**
     * Verify signatures and decrypt all received ballots
     * 
     * @return verification results
     */
    public Map<String, Object> verifyAndDecryptBallots() {
        if (votingOpen) {
            System.out.println("❌ Cannot verify ballots while voting is open");
            return createErrorResult("Voting still open");
        }

        System.out.println("🔐 Verifying and decrypting ballots...");

        Map<String, Object> verificationResults = new HashMap<>();
        verificationResults.put("totalBallots", receivedBallots.size());
        verificationResults.put("verifiedBallots", 0);
        verificationResults.put("invalidBallots", 0);
        verificationResults.put("duplicateTokens", 0);
        verificationResults.put("invalidSignatures", 0);
        verificationResults.put("decryptionErrors", 0);

        for (int i = 0; i < receivedBallots.size(); i++) {
            Map<String, Object> votePackage = receivedBallots.get(i);
            System.out.println("   Processing ballot " + (i + 1) + "/" + receivedBallots.size() + "...");

            try {
                // Decrypt the ballot
                String encryptedBallot = (String) votePackage.get("encryptedBallot");
                String decryptedBallotJSON = CryptoUtils.rsaDecrypt(encryptedBallot, eaKeyPair.getPrivate());
                Map<String, Object> ballotData = parseJSON(decryptedBallotJSON);

                // Verify the voter's signature if public key is available
                if (votePackage.containsKey("voterPublicKey")) {
                    String voterSignature = (String) votePackage.get("voterSignature");
                    String voterPublicKeyString = (String) votePackage.get("voterPublicKey");
                    PublicKey voterPublicKey = CryptoUtils.decodePublicKey(voterPublicKeyString);

                    boolean signatureValid = CryptoUtils.verifySignature(decryptedBallotJSON, voterSignature,
                            voterPublicKey);

                    if (!signatureValid) {
                        System.out.println("      ❌ Invalid signature");
                        verificationResults.put("invalidSignatures",
                                (Integer) verificationResults.get("invalidSignatures") + 1);
                        continue;
                    }
                }

                // Verify vote token with TokenManager
                String voteToken = (String) ballotData.get("voteToken");
                if (!tokenManager.validateAndUseToken(voteToken)) {
                    System.out.println("      ❌ Invalid or duplicate vote token");
                    verificationResults.put("duplicateTokens",
                            (Integer) verificationResults.get("duplicateTokens") + 1);
                    continue;
                }

                // Validate candidate choice
                String candidate = (String) ballotData.get("candidate");
                if (!candidates.contains(candidate)) {
                    System.out.println("      ❌ Invalid candidate: " + candidate);
                    verificationResults.put("invalidBallots", (Integer) verificationResults.get("invalidBallots") + 1);
                    continue;
                }

                // Store verified vote
                Map<String, Object> verifiedVote = new HashMap<>();
                verifiedVote.put("candidate", candidate);
                verifiedVote.put("voteToken", voteToken);
                verifiedVote.put("ballotHash", votePackage.get("ballotHash"));
                verifiedVote.put("timestamp", ballotData.get("timestamp"));
                verifiedVote.put("verifiedTimestamp",
                        LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

                verifiedVotes.add(verifiedVote);
                verificationResults.put("verifiedBallots", (Integer) verificationResults.get("verifiedBallots") + 1);

                System.out.println("      ✅ Valid vote for " + candidate);

            } catch (Exception e) {
                System.out.println("      ❌ Decryption/processing error: " + e.getMessage());
                verificationResults.put("decryptionErrors", (Integer) verificationResults.get("decryptionErrors") + 1);
            }
        }

        System.out.println("\n📊 Verification Results:");
        verificationResults.forEach((key, value) -> System.out.println("   " + key + ": " + value));

        verificationResults.put("success", true);
        return verificationResults;
    }

    /**
     * Count the verified votes
     * 
     * @return election results
     */
    public Map<String, Object> tallyVotes() {
        if (verifiedVotes.isEmpty()) {
            System.out.println("❌ No verified votes to tally");
            return new HashMap<>();
        }

        System.out.println("📊 Tallying votes...");

        // Reset vote counts
        for (String candidate : candidates) {
            voteCounts.put(candidate, 0);
        }

        // Count votes
        for (Map<String, Object> vote : verifiedVotes) {
            String candidate = (String) vote.get("candidate");
            voteCounts.put(candidate, voteCounts.get(candidate) + 1);
        }

        // Calculate results
        int totalVotes = verifiedVotes.size();
        Map<String, Object> results = new HashMap<>();
        results.put("electionName", electionName);
        results.put("electionID", electionID);
        results.put("totalVotes", totalVotes);
        results.put("voteCounts", new HashMap<>(voteCounts));

        // Calculate percentages
        Map<String, Double> votePercentages = new HashMap<>();
        for (Map.Entry<String, Integer> entry : voteCounts.entrySet()) {
            double percentage = totalVotes > 0 ? (entry.getValue() * 100.0 / totalVotes) : 0.0;
            votePercentages.put(entry.getKey(), percentage);
        }
        results.put("votePercentages", votePercentages);

        // Determine winner
        String winner = voteCounts.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(null);
        results.put("winner", winner);
        results.put("tallyTimestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

        System.out.println("\n🏆 Election Results for " + electionName + ":");
        System.out.println("   Total Votes: " + totalVotes);
        for (Map.Entry<String, Integer> entry : voteCounts.entrySet()) {
            double percentage = votePercentages.get(entry.getKey());
            System.out.println("   " + entry.getKey() + ": " + entry.getValue() + " votes ("
                    + String.format("%.1f", percentage) + "%)");
        }
        if (winner != null) {
            System.out.println("   🥇 Winner: " + winner);
        }

        electionComplete = true;
        return results;
    }

    /**
     * Generate audit trail for election transparency
     * 
     * @return audit information
     */
    public Map<String, Object> generateAuditTrail() {
        List<String> ballotHashes = new ArrayList<>();
        for (Map<String, Object> vote : verifiedVotes) {
            ballotHashes.add((String) vote.get("ballotHash"));
        }

        Map<String, Object> auditTrail = new HashMap<>();
        auditTrail.put("electionID", electionID);
        auditTrail.put("electionName", electionName);
        auditTrail.put("candidates", new ArrayList<>(candidates));
        auditTrail.put("totalRegisteredVoters", registeredVoters.size());
        auditTrail.put("totalTokensIssued", tokenManager.getTotalIssuedTokens());
        auditTrail.put("totalBallotsReceived", receivedBallots.size());
        auditTrail.put("totalVerifiedVotes", verifiedVotes.size());
        auditTrail.put("ballotHashes", ballotHashes);
        auditTrail.put("auditTimestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        auditTrail.put("eaPublicKey", CryptoUtils.encodePublicKey(eaKeyPair.getPublic()));

        return auditTrail;
    }

    /**
     * Helper method to create error result
     */
    private Map<String, Object> createErrorResult(String error) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", false);
        result.put("error", error);
        return result;
    }

    /**
     * Simple JSON parsing utility
     * 
     * @param json JSON string to parse
     * @return map representation
     */
    private Map<String, Object> parseJSON(String json) {
        Map<String, Object> map = new HashMap<>();
        String content = json.substring(1, json.length() - 1);
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
    public String getElectionID() {
        return electionID;
    }

    public String getElectionName() {
        return electionName;
    }

    public List<String> getCandidates() {
        return new ArrayList<>(candidates);
    }

    public PublicKey getPublicKey() {
        return eaKeyPair.getPublic();
    }

    public boolean isRegistrationOpen() {
        return registrationOpen;
    }

    public boolean isVotingOpen() {
        return votingOpen;
    }

    public boolean isElectionComplete() {
        return electionComplete;
    }

    public int getRegisteredVotersCount() {
        return registeredVoters.size();
    }

    public int getReceivedBallotsCount() {
        return receivedBallots.size();
    }

    public int getVerifiedVotesCount() {
        return verifiedVotes.size();
    }

    /**
     * Test the ElectionAuthority class functionality
     */
    public static void main(String[] args) {
        try {
            System.out.println("🏛️ Testing ElectionAuthority Class...");

            // Create Election Authority
            System.out.println("\n1. Creating Election Authority...");
            List<String> candidates = Arrays.asList("Alice", "Bob", "Charlie");
            ElectionAuthority ea = new ElectionAuthority("Class President Election 2025", candidates);

            // Test voter registration
            System.out.println("\n2. Testing voter registration...");
            Map<String, Object> voterInfo = new HashMap<>();
            voterInfo.put("voterID", "VOTER_TEST001");
            voterInfo.put("name", "Test Voter");
            voterInfo.put("studentID", "STU001");
            voterInfo.put("email", "test@university.edu");
            voterInfo.put("publicKey", CryptoUtils.encodePublicKey(CryptoUtils.generateRSAKeyPair().getPublic()));

            boolean registrationSuccess = ea.registerVoter(voterInfo);
            System.out.println("Registration: " + (registrationSuccess ? "SUCCESS" : "FAILED"));

            // Close registration and issue tokens
            System.out.println("\n3. Closing registration and issuing tokens...");
            ea.closeRegistration();
            Map<String, String> tokens = ea.issueVoteTokens();
            System.out.println("Tokens issued: " + tokens.size());

            // Open voting
            System.out.println("\n4. Opening voting...");
            boolean votingOpened = ea.openVoting();
            System.out.println("Voting opened: " + (votingOpened ? "SUCCESS" : "FAILED"));

            // Generate audit trail
            System.out.println("\n5. Generating audit trail...");
            Map<String, Object> auditTrail = ea.generateAuditTrail();
            System.out.println("Audit trail keys: " + auditTrail.keySet());

            System.out.println("\n🎉 All ElectionAuthority tests completed!");

        } catch (Exception e) {
            System.err.println("❌ Error during testing: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
