package com.voting.security;

import com.voting.crypto.CryptoUtils;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Mix Network for anonymous ballot submission
 * Provides anonymity layer by shuffling and re-encrypting ballots
 */
public class MixNetwork {

    /**
     * Represents a single node in the mix network
     */
    public static class MixNode {
        private final String nodeID;
        private final KeyPair keyPair;
        private final List<String> processedBallots;
        private final List<Map<String, Object>> processingLog;

        /**
         * Constructor for MixNode
         * 
         * @param nodeID unique identifier for the mix node
         */
        public MixNode(String nodeID) {
            this.nodeID = nodeID;
            this.processedBallots = new ArrayList<>();
            this.processingLog = new ArrayList<>();

            try {
                this.keyPair = CryptoUtils.generateRSAKeyPair();
            } catch (Exception e) {
                throw new RuntimeException("Failed to generate keys for mix node", e);
            }

            System.out.println("🔄 Mix Node " + nodeID + " initialized");
        }

        /**
         * Re-encrypt a ballot for the next layer of anonymization
         * 
         * @param encryptedBallot already encrypted ballot
         * @param nextPublicKey   public key for next encryption layer
         * @return re-encrypted ballot
         * @throws Exception if re-encryption fails
         */
        public String reEncryptBallot(String encryptedBallot, PublicKey nextPublicKey) throws Exception {
            // In a real implementation, this would use proper onion encryption
            // For this demo, we'll simulate re-encryption by adding another layer
            String reEncrypted = CryptoUtils.rsaEncrypt(encryptedBallot, nextPublicKey);

            Map<String, Object> logEntry = new HashMap<>();
            logEntry.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            logEntry.put("action", "re_encrypt");
            logEntry.put("inputHash", CryptoUtils.sha256Hash(encryptedBallot));
            logEntry.put("outputHash", CryptoUtils.sha256Hash(reEncrypted));
            processingLog.add(logEntry);

            return reEncrypted;
        }

        /**
         * Shuffle the order of ballots to prevent timing analysis
         * 
         * @param ballots list of ballots to shuffle
         * @return shuffled ballots
         */
        public List<String> shuffleBallots(List<String> ballots) {
            List<String> shuffled = new ArrayList<>(ballots);
            Collections.shuffle(shuffled, new Random());

            Map<String, Object> logEntry = new HashMap<>();
            logEntry.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            logEntry.put("action", "shuffle");
            logEntry.put("inputCount", ballots.size());
            logEntry.put("outputCount", shuffled.size());
            processingLog.add(logEntry);

            System.out.println("🔄 Node " + nodeID + ": Shuffled " + ballots.size() + " ballots");
            return shuffled;
        }

        /**
         * Add random delay to prevent timing correlation attacks
         */
        public void addRandomDelay() {
            try {
                double delay = 0.1 + Math.random() * 0.4; // 100-500ms delay
                Thread.sleep((long) (delay * 1000));

                Map<String, Object> logEntry = new HashMap<>();
                logEntry.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                logEntry.put("action", "delay");
                logEntry.put("delaySeconds", delay);
                processingLog.add(logEntry);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        /**
         * Process a batch of ballots through this mix node
         * 
         * @param ballots       ballots to process
         * @param nextPublicKey public key for next layer (optional)
         * @return processed ballots
         * @throws Exception if processing fails
         */
        public List<String> processBatch(List<String> ballots, PublicKey nextPublicKey) throws Exception {
            System.out.println("🔄 Node " + nodeID + ": Processing batch of " + ballots.size() + " ballots");

            // Add random delay
            addRandomDelay();

            // Re-encrypt if next public key provided
            List<String> processedBallots = new ArrayList<>();
            if (nextPublicKey != null) {
                for (String ballot : ballots) {
                    processedBallots.add(reEncryptBallot(ballot, nextPublicKey));
                }
            } else {
                processedBallots = new ArrayList<>(ballots);
            }

            // Shuffle ballots
            List<String> shuffledBallots = shuffleBallots(processedBallots);

            // Store processed ballots
            this.processedBallots.addAll(shuffledBallots);

            return shuffledBallots;
        }

        // Getters
        public String getNodeID() {
            return nodeID;
        }

        public PublicKey getPublicKey() {
            return keyPair.getPublic();
        }

        public List<String> getProcessedBallots() {
            return new ArrayList<>(processedBallots);
        }

        public List<Map<String, Object>> getProcessingLog() {
            return new ArrayList<>(processingLog);
        }
    }

    private final int numNodes;
    private final List<MixNode> mixNodes;
    private final String networkID;
    private final String creationTimestamp;

    /**
     * Constructor for MixNetwork
     * 
     * @param numNodes number of mix nodes to create
     */
    public MixNetwork(int numNodes) {
        this.numNodes = numNodes;
        this.mixNodes = new ArrayList<>();
        this.networkID = "MIXNET_" + CryptoUtils.generateSecureToken(8);
        this.creationTimestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        // Create mix nodes
        for (int i = 0; i < numNodes; i++) {
            MixNode node = new MixNode("NODE_" + (i + 1));
            mixNodes.add(node);
        }

        System.out.println("🌐 Mix Network initialized with " + numNodes + " nodes");
        System.out.println("   Network ID: " + networkID);
    }

    /**
     * Default constructor with 3 nodes
     */
    public MixNetwork() {
        this(3);
    }

    /**
     * Submit a vote package through the mix network for anonymization
     * 
     * @param votePackage vote package to anonymize
     * @return anonymized vote package
     * @throws Exception if anonymization fails
     */
    public Map<String, Object> submitBallotAnonymously(Map<String, Object> votePackage) throws Exception {
        System.out.println("🎭 Submitting ballot through mix network...");

        // Extract encrypted ballot from vote package
        String encryptedBallot = (String) votePackage.get("encryptedBallot");
        String currentBallot = encryptedBallot;

        // Process through each mix node
        for (int i = 0; i < mixNodes.size(); i++) {
            MixNode node = mixNodes.get(i);
            System.out.println("   Processing through Node " + (i + 1) + "...");

            // Get next node's public key (or null for last node)
            PublicKey nextPublicKey = (i < mixNodes.size() - 1) ? mixNodes.get(i + 1).getPublicKey() : null;

            // Process ballot through current node
            List<String> processedBallots = node.processBatch(Arrays.asList(currentBallot), nextPublicKey);
            currentBallot = processedBallots.get(0);
        }

        // Create anonymized vote package
        Map<String, Object> anonymizedPackage = new HashMap<>(votePackage);
        anonymizedPackage.put("encryptedBallot", currentBallot);
        anonymizedPackage.put("mixNetworkID", networkID);
        anonymizedPackage.put("anonymizationTimestamp",
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

        // Remove voter-identifying information
        anonymizedPackage.remove("voterPublicKey");

        // Add anonymization proof
        Map<String, Object> anonymizationProof = new HashMap<>();
        anonymizationProof.put("networkID", networkID);
        anonymizationProof.put("nodesTraversed", mixNodes.size());
        anonymizationProof.put("processingHash", CryptoUtils.sha256Hash(currentBallot));
        anonymizationProof.put("anonymizationComplete", true);
        anonymizedPackage.put("anonymizationProof", anonymizationProof);

        System.out.println("✅ Ballot anonymized successfully");
        return anonymizedPackage;
    }

    /**
     * Process multiple ballots together for better anonymity
     * 
     * @param votePackages list of vote packages to process
     * @return anonymized vote packages
     * @throws Exception if processing fails
     */
    public List<Map<String, Object>> processBallotBatch(List<Map<String, Object>> votePackages) throws Exception {
        System.out.println("🎭 Processing batch of " + votePackages.size() + " ballots...");

        if (votePackages.isEmpty()) {
            return new ArrayList<>();
        }

        // Extract encrypted ballots
        List<String> encryptedBallots = new ArrayList<>();
        for (Map<String, Object> pkg : votePackages) {
            encryptedBallots.add((String) pkg.get("encryptedBallot"));
        }

        List<String> currentBallots = new ArrayList<>(encryptedBallots);

        // Process through each mix node
        for (int i = 0; i < mixNodes.size(); i++) {
            MixNode node = mixNodes.get(i);
            System.out.println("   Batch processing through Node " + (i + 1) + "...");

            // Get next node's public key (or null for last node)
            PublicKey nextPublicKey = (i < mixNodes.size() - 1) ? mixNodes.get(i + 1).getPublicKey() : null;

            // Process all ballots through current node
            currentBallots = node.processBatch(currentBallots, nextPublicKey);
        }

        // Create anonymized vote packages
        List<Map<String, Object>> anonymizedPackages = new ArrayList<>();

        for (int i = 0; i < votePackages.size(); i++) {
            Map<String, Object> originalPackage = votePackages.get(i);
            Map<String, Object> anonymizedPackage = new HashMap<>(originalPackage);

            anonymizedPackage.put("encryptedBallot", currentBallots.get(i));
            anonymizedPackage.put("mixNetworkID", networkID);
            anonymizedPackage.put("anonymizationTimestamp",
                    LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

            // Remove voter-identifying information
            anonymizedPackage.remove("voterPublicKey");

            // Add anonymization proof
            Map<String, Object> anonymizationProof = new HashMap<>();
            anonymizationProof.put("networkID", networkID);
            anonymizationProof.put("nodesTraversed", mixNodes.size());
            anonymizationProof.put("batchSize", votePackages.size());
            anonymizationProof.put("processingHash", CryptoUtils.sha256Hash(currentBallots.get(i)));
            anonymizationProof.put("anonymizationComplete", true);
            anonymizedPackage.put("anonymizationProof", anonymizationProof);

            anonymizedPackages.add(anonymizedPackage);
        }

        System.out.println("✅ Batch of " + anonymizedPackages.size() + " ballots anonymized");
        return anonymizedPackages;
    }

    /**
     * Get statistics about the mix network operation
     * 
     * @return network statistics
     */
    public Map<String, Object> getNetworkStatistics() {
        int totalProcessed = 0;
        for (MixNode node : mixNodes) {
            totalProcessed += node.getProcessedBallots().size();
        }

        Map<String, Object> statistics = new HashMap<>();
        statistics.put("networkID", networkID);
        statistics.put("numNodes", numNodes);
        statistics.put("totalBallotsProcessed", totalProcessed);
        statistics.put("creationTimestamp", creationTimestamp);
        statistics.put("statisticsTimestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

        List<Map<String, Object>> nodeStatistics = new ArrayList<>();
        for (MixNode node : mixNodes) {
            Map<String, Object> nodeStats = new HashMap<>();
            nodeStats.put("nodeID", node.getNodeID());
            nodeStats.put("ballotsProcessed", node.getProcessedBallots().size());
            nodeStats.put("operationsPerformed", node.getProcessingLog().size());
            nodeStatistics.add(nodeStats);
        }
        statistics.put("nodeStatistics", nodeStatistics);

        return statistics;
    }

    /**
     * Generate audit trail for anonymization process
     * 
     * @return anonymization audit trail
     */
    public Map<String, Object> generateAnonymizationAudit() {
        Map<String, Object> auditTrail = new HashMap<>();
        auditTrail.put("networkID", networkID);
        auditTrail.put("auditTimestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

        Map<String, Object> networkConfiguration = new HashMap<>();
        networkConfiguration.put("numNodes", numNodes);
        List<String> nodeIDs = new ArrayList<>();
        for (MixNode node : mixNodes) {
            nodeIDs.add(node.getNodeID());
        }
        networkConfiguration.put("nodeIDs", nodeIDs);
        auditTrail.put("networkConfiguration", networkConfiguration);

        // Collect processing logs from all nodes
        List<Map<String, Object>> processingLogs = new ArrayList<>();
        for (MixNode node : mixNodes) {
            Map<String, Object> nodeLog = new HashMap<>();
            nodeLog.put("nodeID", node.getNodeID());
            try {
                nodeLog.put("publicKeyHash", CryptoUtils.sha256Hash(CryptoUtils.encodePublicKey(node.getPublicKey())));
            } catch (Exception e) {
                nodeLog.put("publicKeyHash", "error");
            }
            nodeLog.put("operations", new ArrayList<>(node.getProcessingLog()));
            processingLogs.add(nodeLog);
        }
        auditTrail.put("processingLogs", processingLogs);

        return auditTrail;
    }

    /**
     * Verify that anonymization was performed correctly
     * 
     * @param originalPackage   original vote package
     * @param anonymizedPackage anonymized vote package
     * @return verification results
     */
    public Map<String, Object> verifyAnonymization(Map<String, Object> originalPackage,
            Map<String, Object> anonymizedPackage) {
        Map<String, Object> verification = new HashMap<>();
        verification.put("isValid", false);
        List<String> checksPasssed = new ArrayList<>();
        List<String> checksFailed = new ArrayList<>();

        // Check that ballot ID is preserved
        if (Objects.equals(originalPackage.get("ballotID"), anonymizedPackage.get("ballotID"))) {
            checksPasssed.add("ballot_id_preserved");
        } else {
            checksFailed.add("ballot_id_mismatch");
        }

        // Check that voter public key is removed
        if (!anonymizedPackage.containsKey("voterPublicKey")) {
            checksPasssed.add("voter_identity_removed");
        } else {
            checksFailed.add("voter_identity_present");
        }

        // Check that anonymization proof exists
        if (anonymizedPackage.containsKey("anonymizationProof")) {
            checksPasssed.add("anonymization_proof_present");
        } else {
            checksFailed.add("anonymization_proof_missing");
        }

        // Check that encrypted ballot was modified (re-encrypted)
        if (!Objects.equals(originalPackage.get("encryptedBallot"), anonymizedPackage.get("encryptedBallot"))) {
            checksPasssed.add("ballot_re_encrypted");
        } else {
            checksFailed.add("ballot_not_re_encrypted");
        }

        // Overall verification
        verification.put("isValid", checksFailed.isEmpty());
        verification.put("checksPasssed", checksPasssed);
        verification.put("checksFailed", checksFailed);
        verification.put("anonymizationVerified", checksFailed.isEmpty());

        return verification;
    }

    // Getters
    public String getNetworkID() {
        return networkID;
    }

    public int getNumNodes() {
        return numNodes;
    }

    public List<MixNode> getMixNodes() {
        return new ArrayList<>(mixNodes);
    }

    /**
     * Test the MixNetwork class functionality
     */
    public static void main(String[] args) {
        try {
            System.out.println("🎭 Testing MixNetwork Class...");

            // Create mix network
            System.out.println("\n1. Creating Mix Network...");
            MixNetwork mixNetwork = new MixNetwork(3);

            // Create test vote packages
            System.out.println("\n2. Creating test vote packages...");
            KeyPair eaKeyPair = CryptoUtils.generateRSAKeyPair();
            KeyPair voterKeyPair = CryptoUtils.generateRSAKeyPair();

            // Create mock vote package
            Map<String, Object> testBallot = new HashMap<>();
            testBallot.put("voteToken", CryptoUtils.generateSecureToken(16));
            testBallot.put("candidate", "Test Candidate");
            testBallot.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

            String ballotJSON = mapToJSON(testBallot);
            String encryptedBallot = CryptoUtils.rsaEncrypt(ballotJSON, eaKeyPair.getPublic());
            String signature = CryptoUtils.signMessage(ballotJSON, voterKeyPair.getPrivate());

            Map<String, Object> votePackage = new HashMap<>();
            votePackage.put("ballotID", CryptoUtils.generateBallotID());
            votePackage.put("encryptedBallot", encryptedBallot);
            votePackage.put("voterSignature", signature);
            votePackage.put("voterPublicKey", CryptoUtils.encodePublicKey(voterKeyPair.getPublic()));
            votePackage.put("ballotHash", CryptoUtils.sha256Hash(ballotJSON));
            votePackage.put("submissionTimestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

            System.out.println("Test vote package created");

            // Test single ballot anonymization
            System.out.println("\n3. Testing single ballot anonymization...");
            Map<String, Object> anonymizedPackage = mixNetwork.submitBallotAnonymously(votePackage);
            System.out.println("Anonymized package keys: " + anonymizedPackage.keySet());

            // Test batch processing
            System.out.println("\n4. Testing batch processing...");
            List<Map<String, Object>> votePackages = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                Map<String, Object> pkg = new HashMap<>(votePackage);
                pkg.put("ballotID", "BALLOT_" + i);
                pkg.put("ballotHash", CryptoUtils.sha256Hash("ballot_" + i));
                votePackages.add(pkg);
            }

            List<Map<String, Object>> anonymizedBatch = mixNetwork.processBallotBatch(votePackages);
            System.out.println("Batch processed: " + anonymizedBatch.size() + " ballots");

            // Test verification
            System.out.println("\n5. Testing anonymization verification...");
            Map<String, Object> verification = mixNetwork.verifyAnonymization(votePackage, anonymizedPackage);
            System.out.println(
                    "Verification result: " + (Boolean.TRUE.equals(verification.get("isValid")) ? "PASSED" : "FAILED"));
            System.out.println("Checks passed: " + ((List<?>) verification.get("checksPasssed")).size());
            System.out.println("Checks failed: " + ((List<?>) verification.get("checksFailed")).size());

            // Get network statistics
            System.out.println("\n6. Getting network statistics...");
            Map<String, Object> stats = mixNetwork.getNetworkStatistics();
            System.out.println("Total ballots processed: " + stats.get("totalBallotsProcessed"));
            System.out.println("Number of nodes: " + stats.get("numNodes"));

            // Generate audit trail
            System.out.println("\n7. Generating audit trail...");
            Map<String, Object> audit = mixNetwork.generateAnonymizationAudit();
            List<?> processingLogs = (List<?>) audit.get("processingLogs");
            System.out.println("Audit trail generated with " + processingLogs.size() + " node logs");

            System.out.println("\n🎉 All MixNetwork tests completed!");

        } catch (Exception e) {
            System.err.println("❌ Error during testing: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Simple JSON conversion utility
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
}
