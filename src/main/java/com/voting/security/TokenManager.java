package com.voting.security;

import com.voting.core.VoteToken;
import com.voting.crypto.CryptoUtils;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Manages vote tokens to ensure one vote per voter and prevent double voting
 * Handles token generation, validation, and tracking for election security
 */
public class TokenManager {

    private final String electionID;
    private final Map<String, VoteToken> issuedTokens; // tokenValue -> VoteToken mapping
    private final Set<String> usedTokens; // Set of used token values
    private final Set<String> tokenBlacklist; // Blacklisted token values
    private final Map<String, String> voterTokenMap; // voterID -> tokenValue mapping
    private final String creationTimestamp;

    /**
     * Constructor for TokenManager
     * 
     * @param electionID unique identifier for the election
     */
    public TokenManager(String electionID) {
        this.electionID = electionID;
        this.issuedTokens = new HashMap<>();
        this.usedTokens = new HashSet<>();
        this.tokenBlacklist = new HashSet<>();
        this.voterTokenMap = new HashMap<>();
        this.creationTimestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        System.out.println("🎫 Token Manager initialized for election: " + electionID);
    }

    /**
     * Generate and issue a vote token for a voter
     * 
     * @param voterID        unique voter identifier
     * @param voterPublicKey voter's public key for encryption
     * @return encrypted token for the voter
     * @throws Exception if token generation or encryption fails
     */
    public String generateAndIssueToken(String voterID, PublicKey voterPublicKey) throws Exception {
        System.out.println("🎫 Generating vote token for voter: " + voterID);

        // Check if voter already has a token
        if (voterTokenMap.containsKey(voterID)) {
            System.out.println("❌ Voter " + voterID + " already has a token");
            throw new IllegalStateException("Voter already has a token");
        }

        // Create new vote token
        VoteToken voteToken = new VoteToken(voterID);
        String tokenValue = voteToken.getTokenValue();

        // Ensure token uniqueness
        while (issuedTokens.containsKey(tokenValue) || tokenBlacklist.contains(tokenValue)) {
            voteToken = new VoteToken(voterID); // Generate new token
            tokenValue = voteToken.getTokenValue();
        }

        // Store token
        issuedTokens.put(tokenValue, voteToken);
        voterTokenMap.put(voterID, tokenValue);

        // Encrypt token for voter
        String encryptedToken = voteToken.encryptForVoter(voterPublicKey);

        System.out.println("✅ Token generated and encrypted for " + voterID);
        System.out.println("   Token ID: " + voteToken.getTokenID());

        return encryptedToken;
    }

    /**
     * Validate a vote token
     * 
     * @param tokenValue token value to validate
     * @return validation result
     */
    public VoteToken.TokenValidationResult validateToken(String tokenValue) {
        VoteToken.TokenValidationResult result = new VoteToken.TokenValidationResult();
        result.isValid = false;

        // Check if token exists
        if (!issuedTokens.containsKey(tokenValue)) {
            result.reason = "Token not found";
            return result;
        }

        VoteToken token = issuedTokens.get(tokenValue);
        return token.validate();
    }

    /**
     * Validate and mark a token as used (for vote casting)
     * 
     * @param tokenValue token value to validate and use
     * @return true if token was valid and successfully marked as used
     */
    public boolean validateAndUseToken(String tokenValue) {
        System.out.println("🔍 Validating and using token: " + tokenValue.substring(0, 8) + "...");

        VoteToken.TokenValidationResult validation = validateToken(tokenValue);

        if (!validation.isValid) {
            System.out.println("❌ Token validation failed: " + validation.reason);
            return false;
        }

        VoteToken token = issuedTokens.get(tokenValue);
        boolean marked = token.markAsUsed();

        if (marked) {
            usedTokens.add(tokenValue);
            System.out.println("✅ Token validated and marked as used");
        }

        return marked;
    }

    /**
     * Blacklist a token
     * 
     * @param tokenValue token value to blacklist
     * @param reason     reason for blacklisting
     */
    public void blacklistToken(String tokenValue, String reason) {
        tokenBlacklist.add(tokenValue);

        // Update token if it exists
        if (issuedTokens.containsKey(tokenValue)) {
            VoteToken token = issuedTokens.get(tokenValue);
            token.blacklist(reason);
        }

        System.out.println("🚫 Token blacklisted: " + tokenValue.substring(0, 8) + "...");
        System.out.println("   Reason: " + reason);
    }

    /**
     * Get token statistics
     * 
     * @return map containing token usage statistics
     */
    public Map<String, Object> getTokenStatistics() {
        int totalIssued = issuedTokens.size();
        int usedCount = usedTokens.size();
        int blacklistedCount = tokenBlacklist.size();
        int unusedCount = totalIssued - usedCount;

        Map<String, Object> statistics = new HashMap<>();
        statistics.put("electionID", electionID);
        statistics.put("totalTokensIssued", totalIssued);
        statistics.put("tokensUsed", usedCount);
        statistics.put("tokensUnused", unusedCount);
        statistics.put("tokensBlacklisted", blacklistedCount);
        statistics.put("usageRate", totalIssued > 0 ? (usedCount * 100.0 / totalIssued) : 0.0);
        statistics.put("statisticsTimestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

        return statistics;
    }

    /**
     * Get token status for a specific voter
     * 
     * @param voterID voter ID to check
     * @return voter's token status
     */
    public Map<String, Object> getVoterTokenStatus(String voterID) {
        if (!voterTokenMap.containsKey(voterID)) {
            Map<String, Object> status = new HashMap<>();
            status.put("voterID", voterID);
            status.put("hasToken", false);
            status.put("tokenStatus", "No token issued");
            return status;
        }

        String tokenValue = voterTokenMap.get(voterID);
        VoteToken token = issuedTokens.get(tokenValue);
        Map<String, Object> tokenInfo = token.getTokenInfo();

        Map<String, Object> status = new HashMap<>();
        status.put("voterID", voterID);
        status.put("hasToken", true);
        status.put("tokenID", token.getTokenID());
        status.put("issueTimestamp", token.getIssueTimestamp());
        status.put("isUsed", token.isUsed());
        status.put("usageTimestamp", token.getUsageTimestamp());
        status.put("isBlacklisted", token.isBlacklisted());
        status.put("tokenStatus", token.getStatus());

        return status;
    }

    /**
     * Export token audit log for transparency
     * 
     * @return complete audit log (without sensitive token values)
     */
    public Map<String, Object> exportTokenAuditLog() {
        Map<String, Object> auditLog = new HashMap<>();
        auditLog.put("electionID", electionID);
        auditLog.put("creationTimestamp", creationTimestamp);
        auditLog.put("auditTimestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        auditLog.put("statistics", getTokenStatistics());

        List<Map<String, Object>> tokenRecords = new ArrayList<>();

        // Add anonymized token records
        for (VoteToken token : issuedTokens.values()) {
            tokenRecords.add(token.getAnonymizedInfo());
        }

        auditLog.put("tokenRecords", tokenRecords);
        return auditLog;
    }

    /**
     * Detect suspicious token activity
     * 
     * @return list of suspicious activities detected
     */
    public List<Map<String, Object>> detectSuspiciousActivity() {
        List<Map<String, Object>> suspiciousActivities = new ArrayList<>();

        Map<String, Object> stats = getTokenStatistics();
        int totalIssued = (Integer) stats.get("totalTokensIssued");
        int blacklisted = (Integer) stats.get("tokensBlacklisted");
        double usageRate = (Double) stats.get("usageRate");

        // Check for high blacklist rate
        if (totalIssued > 0 && blacklisted > totalIssued * 0.1) { // More than 10%
            Map<String, Object> activity = new HashMap<>();
            activity.put("type", "high_blacklist_rate");
            activity.put("description", "High number of blacklisted tokens: " + blacklisted);
            activity.put("severity", "medium");
            activity.put("detectedAt", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            suspiciousActivities.add(activity);
        }

        // Check for low usage rate (potential voter suppression)
        if (totalIssued > 10 && usageRate < 50) {
            Map<String, Object> activity = new HashMap<>();
            activity.put("type", "low_usage_rate");
            activity.put("description", String.format("Low token usage rate: %.1f%%", usageRate));
            activity.put("severity", "low");
            activity.put("detectedAt", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            suspiciousActivities.add(activity);
        }

        return suspiciousActivities;
    }

    /**
     * Get total number of issued tokens
     * 
     * @return total issued tokens count
     */
    public int getTotalIssuedTokens() {
        return issuedTokens.size();
    }

    /**
     * Get total number of used tokens
     * 
     * @return total used tokens count
     */
    public int getTotalUsedTokens() {
        return usedTokens.size();
    }

    /**
     * Check if a voter has been issued a token
     * 
     * @param voterID voter ID to check
     * @return true if voter has a token
     */
    public boolean hasVoterToken(String voterID) {
        return voterTokenMap.containsKey(voterID);
    }

    /**
     * Get list of all voter IDs that have tokens
     * 
     * @return array of voter IDs
     */
    public String[] getVotersWithTokens() {
        return voterTokenMap.keySet().toArray(new String[0]);
    }

    /**
     * Reset token manager (for testing purposes)
     */
    public void reset() {
        issuedTokens.clear();
        usedTokens.clear();
        tokenBlacklist.clear();
        voterTokenMap.clear();
        System.out.println("🔄 Token Manager reset");
    }

    /**
     * Test the TokenManager class functionality
     */
    public static void main(String[] args) {
        try {
            System.out.println("🎫 Testing TokenManager Class...");

            // Create Token Manager
            System.out.println("\n1. Creating Token Manager...");
            String electionID = "ELECTION_2025_001";
            TokenManager tokenManager = new TokenManager(electionID);

            // Generate test keys for voters
            System.out.println("\n2. Generating test voter keys...");
            KeyPair voter1KeyPair = CryptoUtils.generateRSAKeyPair();
            KeyPair voter2KeyPair = CryptoUtils.generateRSAKeyPair();

            // Generate tokens for voters
            System.out.println("\n3. Generating vote tokens...");
            String token1 = tokenManager.generateAndIssueToken("VOTER_001", voter1KeyPair.getPublic());
            String token2 = tokenManager.generateAndIssueToken("VOTER_002", voter2KeyPair.getPublic());

            System.out.println("Tokens generated: " + (token1 != null && token2 != null));

            // Test token validation (need to decrypt first for testing)
            System.out.println("\n4. Testing token validation...");
            // In real scenario, voter would decrypt the token
            String voterID1 = "VOTER_001";
            String tokenValue1 = tokenManager.voterTokenMap.get(voterID1);
            VoteToken.TokenValidationResult validation1 = tokenManager.validateToken(tokenValue1);
            System.out.println("Token 1 validation: " + validation1.isValid + " - " + validation1.reason);

            // Test invalid token
            String invalidToken = "INVALID_TOKEN_123";
            VoteToken.TokenValidationResult validationInvalid = tokenManager.validateToken(invalidToken);
            System.out.println(
                    "Invalid token validation: " + validationInvalid.isValid + " - " + validationInvalid.reason);

            // Mark token as used
            System.out.println("\n5. Testing token usage marking...");
            boolean markSuccess = tokenManager.validateAndUseToken(tokenValue1);
            System.out.println("Token marking: " + (markSuccess ? "SUCCESS" : "FAILED"));

            // Test double usage prevention
            System.out.println("\n6. Testing double usage prevention...");
            VoteToken.TokenValidationResult validationUsed = tokenManager.validateToken(tokenValue1);
            System.out.println("Used token validation: " + validationUsed.isValid + " - " + validationUsed.reason);

            // Test token blacklisting
            System.out.println("\n7. Testing token blacklisting...");
            String voterID2 = "VOTER_002";
            String tokenValue2 = tokenManager.voterTokenMap.get(voterID2);
            tokenManager.blacklistToken(tokenValue2, "Security test");
            VoteToken.TokenValidationResult validationBlacklisted = tokenManager.validateToken(tokenValue2);
            System.out.println("Blacklisted token validation: " + validationBlacklisted.isValid + " - "
                    + validationBlacklisted.reason);

            // Get statistics
            System.out.println("\n8. Getting token statistics...");
            Map<String, Object> stats = tokenManager.getTokenStatistics();
            System.out.printf("Statistics: %d issued, %d used, %.1f%% rate%n",
                    stats.get("totalTokensIssued"), stats.get("tokensUsed"), stats.get("usageRate"));

            // Check voter status
            System.out.println("\n9. Checking voter token status...");
            Map<String, Object> voterStatus = tokenManager.getVoterTokenStatus("VOTER_001");
            System.out.println("Voter 1 status: " + voterStatus.get("tokenStatus"));

            // Generate audit log
            System.out.println("\n10. Generating audit log...");
            Map<String, Object> auditLog = tokenManager.exportTokenAuditLog();
            List<Map<String, Object>> tokenRecords = (List<Map<String, Object>>) auditLog.get("tokenRecords");
            System.out.println("Audit log created with " + tokenRecords.size() + " records");

            // Detect suspicious activity
            System.out.println("\n11. Detecting suspicious activity...");
            List<Map<String, Object>> suspicious = tokenManager.detectSuspiciousActivity();
            System.out.println("Suspicious activities detected: " + suspicious.size());

            System.out.println("\n🎉 All TokenManager tests completed!");

        } catch (Exception e) {
            System.err.println("❌ Error during testing: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
