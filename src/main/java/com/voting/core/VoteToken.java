package com.voting.core;

import com.voting.crypto.CryptoUtils;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents a vote token in the secure voting system
 * Handles token creation, encryption, and validation
 */
public class VoteToken {

    private String tokenID;
    private String voterID;
    private String tokenValue;
    private String encryptedToken;
    private boolean isUsed;
    private boolean isBlacklisted;
    private String issueTimestamp;
    private String usageTimestamp;
    private String blacklistReason;

    /**
     * Constructor for creating a new vote token
     * 
     * @param voterID the voter ID this token is issued to
     */
    public VoteToken(String voterID) {
        this.tokenID = "TOKEN_" + CryptoUtils.generateSecureToken(8);
        this.voterID = voterID;
        this.tokenValue = CryptoUtils.generateSecureToken(16);
        this.isUsed = false;
        this.isBlacklisted = false;
        this.issueTimestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        System.out.println("🎫 Vote token created for voter: " + voterID);
        System.out.println("   Token ID: " + tokenID);
    }

    /**
     * Constructor for loading existing token
     * 
     * @param tokenID        existing token ID
     * @param voterID        voter ID
     * @param tokenValue     token value
     * @param isUsed         whether token is used
     * @param issueTimestamp when token was issued
     */
    public VoteToken(String tokenID, String voterID, String tokenValue, boolean isUsed, String issueTimestamp) {
        this.tokenID = tokenID;
        this.voterID = voterID;
        this.tokenValue = tokenValue;
        this.isUsed = isUsed;
        this.isBlacklisted = false;
        this.issueTimestamp = issueTimestamp;
    }

    /**
     * Encrypt the token with voter's public key
     * 
     * @param voterPublicKey the voter's public key for encryption
     * @return encrypted token string
     * @throws Exception if encryption fails
     */
    public String encryptForVoter(PublicKey voterPublicKey) throws Exception {
        System.out.println("🔐 Encrypting token for voter: " + voterID);

        this.encryptedToken = CryptoUtils.rsaEncrypt(tokenValue, voterPublicKey);

        System.out.println("✅ Token encrypted successfully");
        return encryptedToken;
    }

    /**
     * Validate the token for voting
     * 
     * @return validation result
     */
    public TokenValidationResult validate() {
        System.out.println("🔍 Validating token: " + tokenID);

        TokenValidationResult result = new TokenValidationResult();
        result.tokenID = tokenID;
        result.voterID = voterID;

        // Check if token is blacklisted
        if (isBlacklisted) {
            result.isValid = false;
            result.reason = "Token is blacklisted: " + blacklistReason;
            return result;
        }

        // Check if token has already been used
        if (isUsed) {
            result.isValid = false;
            result.reason = "Token already used at: " + usageTimestamp;
            return result;
        }

        // Token is valid
        result.isValid = true;
        result.reason = "Token is valid and ready for use";

        System.out.println("✅ Token validation: " + result.reason);
        return result;
    }

    /**
     * Mark the token as used
     * 
     * @return true if successfully marked as used
     */
    public boolean markAsUsed() {
        if (isUsed) {
            System.out.println("⚠️ Token already marked as used: " + tokenID);
            return false;
        }

        if (isBlacklisted) {
            System.out.println("❌ Cannot use blacklisted token: " + tokenID);
            return false;
        }

        this.isUsed = true;
        this.usageTimestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        System.out.println("✅ Token marked as used: " + tokenID);
        return true;
    }

    /**
     * Blacklist the token
     * 
     * @param reason reason for blacklisting
     */
    public void blacklist(String reason) {
        this.isBlacklisted = true;
        this.blacklistReason = reason;

        System.out.println("🚫 Token blacklisted: " + tokenID);
        System.out.println("   Reason: " + reason);
    }

    /**
     * Get token information (without sensitive token value)
     * 
     * @return map containing token information
     */
    public Map<String, Object> getTokenInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("tokenID", tokenID);
        info.put("voterID", voterID);
        info.put("isUsed", isUsed);
        info.put("isBlacklisted", isBlacklisted);
        info.put("issueTimestamp", issueTimestamp);
        info.put("usageTimestamp", usageTimestamp);
        info.put("blacklistReason", blacklistReason);
        info.put("hasEncryptedToken", encryptedToken != null);
        return info;
    }

    /**
     * Get anonymized token information for audit purposes
     * 
     * @return anonymized token information
     */
    public Map<String, Object> getAnonymizedInfo() {
        Map<String, Object> info = new HashMap<>();
        try {
            info.put("tokenIDHash", CryptoUtils.sha256Hash(tokenID));
            info.put("voterIDHash", CryptoUtils.sha256Hash(voterID));
            info.put("tokenValueHash", CryptoUtils.sha256Hash(tokenValue));
            info.put("isUsed", isUsed);
            info.put("isBlacklisted", isBlacklisted);
            info.put("issueTimestamp", issueTimestamp);
            info.put("usageTimestamp", usageTimestamp);
        } catch (Exception e) {
            System.err.println("Error creating anonymized info: " + e.getMessage());
        }
        return info;
    }

    /**
     * Verify that this token matches the given token value
     * 
     * @param tokenValueToCheck token value to verify
     * @return true if token values match
     */
    public boolean verifyTokenValue(String tokenValueToCheck) {
        return tokenValue.equals(tokenValueToCheck);
    }

    /**
     * Get token status as string
     * 
     * @return string representation of token status
     */
    public String getStatus() {
        if (isBlacklisted) {
            return "BLACKLISTED";
        } else if (isUsed) {
            return "USED";
        } else {
            return "VALID";
        }
    }

    // Getters and setters
    public String getTokenID() {
        return tokenID;
    }

    public String getVoterID() {
        return voterID;
    }

    public String getTokenValue() {
        return tokenValue;
    }

    public String getEncryptedToken() {
        return encryptedToken;
    }

    public boolean isUsed() {
        return isUsed;
    }

    public boolean isBlacklisted() {
        return isBlacklisted;
    }

    public String getIssueTimestamp() {
        return issueTimestamp;
    }

    public String getUsageTimestamp() {
        return usageTimestamp;
    }

    public String getBlacklistReason() {
        return blacklistReason;
    }

    /**
     * Inner class for token validation results
     */
    public static class TokenValidationResult {
        public boolean isValid;
        public String reason;
        public String tokenID;
        public String voterID;

        @Override
        public String toString() {
            return "TokenValidationResult{" +
                    "isValid=" + isValid +
                    ", reason='" + reason + '\'' +
                    ", tokenID='" + tokenID + '\'' +
                    ", voterID='" + voterID + '\'' +
                    '}';
        }
    }

    /**
     * Create a token receipt for voter
     * 
     * @return token receipt information
     */
    public Map<String, Object> createTokenReceipt() {
        Map<String, Object> receipt = new HashMap<>();
        receipt.put("tokenID", tokenID.substring(0, 12) + "..."); // Partial token ID
        receipt.put("voterID", voterID);
        receipt.put("issueTimestamp", issueTimestamp);
        receipt.put("status", getStatus());
        receipt.put("receiptMessage", "Token issued successfully. Keep this receipt safe.");
        return receipt;
    }

    @Override
    public String toString() {
        return "VoteToken{" +
                "tokenID='" + tokenID + '\'' +
                ", voterID='" + voterID + '\'' +
                ", isUsed=" + isUsed +
                ", isBlacklisted=" + isBlacklisted +
                ", status='" + getStatus() + '\'' +
                '}';
    }

    /**
     * Test the VoteToken class functionality
     */
    public static void main(String[] args) {
        try {
            System.out.println("🎫 Testing VoteToken Class...");

            // Create test token
            System.out.println("\n1. Creating vote token...");
            String testVoterID = "VOTER_TEST_001";
            VoteToken token = new VoteToken(testVoterID);
            System.out.println("Token created: " + token);

            // Test token encryption
            System.out.println("\n2. Testing token encryption...");
            KeyPair voterKeyPair = CryptoUtils.generateRSAKeyPair();
            String encryptedToken = token.encryptForVoter(voterKeyPair.getPublic());
            System.out.println("Token encrypted: " + (encryptedToken != null ? "SUCCESS" : "FAILED"));

            // Test token validation
            System.out.println("\n3. Testing token validation...");
            TokenValidationResult validation = token.validate();
            System.out.println("Validation result: " + validation);

            // Test token usage
            System.out.println("\n4. Testing token usage...");
            boolean marked = token.markAsUsed();
            System.out.println("Token marked as used: " + (marked ? "SUCCESS" : "FAILED"));

            // Test double usage prevention
            System.out.println("\n5. Testing double usage prevention...");
            TokenValidationResult usedValidation = token.validate();
            System.out.println("Used token validation: " + usedValidation);

            // Test token blacklisting
            System.out.println("\n6. Testing token blacklisting...");
            VoteToken blacklistToken = new VoteToken("VOTER_TEST_002");
            blacklistToken.blacklist("Security test");
            TokenValidationResult blacklistValidation = blacklistToken.validate();
            System.out.println("Blacklisted token validation: " + blacklistValidation);

            // Test token info
            System.out.println("\n7. Testing token info...");
            Map<String, Object> tokenInfo = token.getTokenInfo();
            System.out.println("Token info: " + tokenInfo);

            Map<String, Object> anonymizedInfo = token.getAnonymizedInfo();
            System.out.println("Anonymized info keys: " + anonymizedInfo.keySet());

            // Test token receipt
            System.out.println("\n8. Testing token receipt...");
            Map<String, Object> receipt = token.createTokenReceipt();
            System.out.println("Token receipt: " + receipt);

            System.out.println("\n🎉 All VoteToken tests completed!");

        } catch (Exception e) {
            System.err.println("❌ Error during testing: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
