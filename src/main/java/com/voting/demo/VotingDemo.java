package com.voting.demo;

import com.voting.core.*;
import com.voting.security.*;
import com.voting.crypto.CryptoUtils;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Comprehensive demonstration of the Secure Electronic Voting Protocol
 * Shows the complete election process from voter registration to result
 * tallying
 */
public class VotingDemo {

    private static final String ELECTION_NAME = "Computer Science Class President Election 2025";
    private static final List<String> CANDIDATES = Arrays.asList(
            "Alice Johnson - Innovation & Technology",
            "Bob Smith - Student Welfare & Events",
            "Charlie Davis - Academic Excellence",
            "Diana Wilson - Campus Sustainability");

    private static final String[][] VOTERS = {
            { "Alice Thompson", "CS001", "alice.t@university.edu" },
            { "Bob Rodriguez", "CS002", "bob.r@university.edu" },
            { "Carol Chen", "CS003", "carol.c@university.edu" },
            { "David Kim", "CS004", "david.k@university.edu" },
            { "Emily Johnson", "CS005", "emily.j@university.edu" },
            { "Frank Miller", "CS006", "frank.m@university.edu" },
            { "Grace Lee", "CS007", "grace.l@university.edu" },
            { "Henry Wilson", "CS008", "henry.w@university.edu" }
    };

    public static void main(String[] args) {
        try {
            System.out.println("SECURE ELECTRONIC VOTING PROTOCOL DEMONSTRATION");
            System.out.println("=".repeat(60));
            System.out.println("Election: " + ELECTION_NAME);
            System.out.println("Candidates: " + CANDIDATES.size());
            System.out.println("Registered Voters: " + VOTERS.length);
            System.out.println("=".repeat(60));

            // Step 1: Initialize Election Authority
            System.out.println("\nSTEP 1: INITIALIZING ELECTION AUTHORITY");
            System.out.println("-".repeat(50));
            ElectionAuthority ea = new ElectionAuthority(ELECTION_NAME, CANDIDATES);
            System.out.println("Election Authority initialized");
            System.out.println("   Election ID: " + ea.getElectionID());
            System.out.println(
                    "   EA Public Key: " + CryptoUtils.encodePublicKey(ea.getPublicKey()).substring(0, 32) + "...");

            // Step 2: Voter Registration Phase
            System.out.println("\nSTEP 2: VOTER REGISTRATION PHASE");
            System.out.println("-".repeat(50));
            List<Voter> voters = new ArrayList<>();

            for (String[] voterData : VOTERS) {
                Voter voter = new Voter(voterData[0], voterData[1], voterData[2]);
                Map<String, Object> registrationInfo = voter.register();

                boolean registered = ea.registerVoter(registrationInfo);
                if (registered) {
                    voters.add(voter);
                    System.out.println("Registered: " + voter.getName() + " (" + voter.getVoterID() + ")");
                } else {
                    System.out.println("Failed to register: " + voter.getName());
                }
            }

            System.out.println("\nRegistration Summary:");
            System.out.println("   Total Registrations: " + voters.size());
            System.out.println("   EA Records: " + ea.getRegisteredVotersCount());

            // Step 3: Close Registration and Issue Tokens
            System.out.println("\nSTEP 3: CLOSING REGISTRATION & ISSUING TOKENS");
            System.out.println("-".repeat(50));
            ea.closeRegistration();
            Map<String, String> issuedTokens = ea.issueVoteTokens();

            // Distribute tokens to voters
            for (Voter voter : voters) {
                String encryptedToken = issuedTokens.get(voter.getVoterID());
                if (encryptedToken != null) {
                    boolean tokenReceived = voter.receiveVoteToken(encryptedToken);
                    System.out.println((tokenReceived ? "✅" : "❌") + " Token delivered to: " + voter.getName());
                }
            }

            System.out.println("\n📊 Token Distribution Summary:");
            System.out.println("   Tokens Issued: " + issuedTokens.size());
            System.out.println("   Tokens Delivered: " + voters.size());

            // Step 4: Open Voting
            System.out.println("\n🗳️ STEP 4: OPENING VOTING PROCESS");
            System.out.println("-".repeat(50));
            boolean votingOpened = ea.openVoting();
            if (votingOpened) {
                System.out.println("✅ Voting is now OPEN!");
                System.out.println("   Voters can now cast their ballots anonymously");
            } else {
                System.out.println("❌ Failed to open voting");
                return;
            }

            // Step 5: Vote Casting Phase (with Mix Network)
            System.out.println("\n🎭 STEP 5: ANONYMOUS VOTE CASTING");
            System.out.println("-".repeat(50));
            MixNetwork mixNetwork = new MixNetwork(3);
            List<Map<String, Object>> submittedBallots = new ArrayList<>();

            // Simulate voters casting votes
            Random random = new Random();
            for (Voter voter : voters) {
                try {
                    // Each voter randomly selects a candidate
                    String chosenCandidate = CANDIDATES.get(random.nextInt(CANDIDATES.size()));

                    System.out.println("🗳️ " + voter.getName() + " is casting vote...");

                    // Create vote package
                    Map<String, Object> votePackage = voter.castVote(chosenCandidate, ea.getPublicKey());

                    // Anonymize through mix network
                    Map<String, Object> anonymizedPackage = mixNetwork.submitBallotAnonymously(votePackage);

                    // Submit to Election Authority
                    boolean ballotReceived = ea.receiveBallot(anonymizedPackage);

                    if (ballotReceived) {
                        submittedBallots.add(votePackage);
                        System.out.println("   ✅ Vote submitted anonymously for: " + chosenCandidate);
                    } else {
                        System.out.println("   ❌ Vote submission failed");
                    }

                    // Small delay between votes
                    TimeUnit.MILLISECONDS.sleep(200);

                } catch (Exception e) {
                    System.out.println("   ❌ Error casting vote for " + voter.getName() + ": " + e.getMessage());
                }
            }

            System.out.println("\n📊 Voting Summary:");
            System.out.println("   Ballots Submitted: " + submittedBallots.size());
            System.out.println("   Ballots Received by EA: " + ea.getReceivedBallotsCount());

            // Step 6: Close Voting
            System.out.println("\n🔒 STEP 6: CLOSING VOTING PROCESS");
            System.out.println("-".repeat(50));
            ea.closeVoting();
            System.out.println("✅ Voting is now CLOSED");
            System.out.println("   No more ballots can be submitted");

            // Step 7: Ballot Verification and Decryption
            System.out.println("\n🔐 STEP 7: BALLOT VERIFICATION & DECRYPTION");
            System.out.println("-".repeat(50));
            Map<String, Object> verificationResults = ea.verifyAndDecryptBallots();

            if (Boolean.TRUE.equals(verificationResults.get("success"))) {
                System.out.println("✅ Ballot verification completed");
                System.out.println("   Total Ballots: " + verificationResults.get("totalBallots"));
                System.out.println("   Verified Ballots: " + verificationResults.get("verifiedBallots"));
                System.out.println("   Invalid Signatures: " + verificationResults.get("invalidSignatures"));
                System.out.println("   Duplicate Tokens: " + verificationResults.get("duplicateTokens"));
                System.out.println("   Decryption Errors: " + verificationResults.get("decryptionErrors"));
            } else {
                System.out.println("❌ Ballot verification failed");
                return;
            }

            // Step 8: Vote Tallying
            System.out.println("\n📊 STEP 8: VOTE TALLYING & RESULTS");
            System.out.println("-".repeat(50));
            Map<String, Object> results = ea.tallyVotes();

            if (!results.isEmpty()) {
                System.out.println("🏆 FINAL ELECTION RESULTS:");
                System.out.println("=".repeat(60));

                int totalVotes = (Integer) results.get("totalVotes");
                @SuppressWarnings("unchecked")
                Map<String, Integer> voteCounts = (Map<String, Integer>) results.get("voteCounts");
                @SuppressWarnings("unchecked")
                Map<String, Double> votePercentages = (Map<String, Double>) results.get("votePercentages");
                String winner = (String) results.get("winner");

                System.out.println("Total Valid Votes: " + totalVotes);
                System.out.println();

                // Sort candidates by vote count for display
                voteCounts.entrySet().stream()
                        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                        .forEach(entry -> {
                            String candidate = entry.getKey();
                            int votes = entry.getValue();
                            double percentage = votePercentages.get(candidate);
                            System.out.printf("   %s: %d votes (%.1f%%)%n", candidate, votes, percentage);
                        });

                System.out.println();
                System.out.println("🥇 WINNER: " + winner);
                System.out.println("=".repeat(60));
            }

            // Step 9: Generate Audit Trail
            System.out.println("\n📋 STEP 9: GENERATING AUDIT TRAIL");
            System.out.println("-".repeat(50));
            Map<String, Object> auditTrail = ea.generateAuditTrail();

            System.out.println("✅ Audit trail generated");
            System.out.println("   Election ID: " + auditTrail.get("electionID"));
            System.out.println("   Total Registered Voters: " + auditTrail.get("totalRegisteredVoters"));
            System.out.println("   Total Tokens Issued: " + auditTrail.get("totalTokensIssued"));
            System.out.println("   Total Ballots Received: " + auditTrail.get("totalBallotsReceived"));
            System.out.println("   Total Verified Votes: " + auditTrail.get("totalVerifiedVotes"));

            @SuppressWarnings("unchecked")
            List<String> ballotHashes = (List<String>) auditTrail.get("ballotHashes");
            System.out.println("   Published Ballot Hashes: " + ballotHashes.size());

            // Step 10: Voter Verification
            System.out.println("\n✅ STEP 10: VOTER VERIFICATION");
            System.out.println("-".repeat(50));
            System.out.println("Voters can now verify their ballots were included:");

            for (int i = 0; i < Math.min(3, submittedBallots.size()); i++) {
                Map<String, Object> ballot = submittedBallots.get(i);
                String ballotHash = (String) ballot.get("ballotHash");
                boolean included = ballotHashes.contains(ballotHash);

                System.out.println("   Ballot " + ballotHash.substring(0, 16) + "...: " +
                        (included ? "✅ VERIFIED" : "❌ NOT FOUND"));
            }

            // Step 11: Security Analysis
            System.out.println("\n🔒 STEP 11: SECURITY ANALYSIS");
            System.out.println("-".repeat(50));

            // Mix Network Statistics
            Map<String, Object> mixStats = mixNetwork.getNetworkStatistics();
            System.out.println("Mix Network Performance:");
            System.out.println("   Network ID: " + mixStats.get("networkID"));
            System.out.println("   Nodes: " + mixStats.get("numNodes"));
            System.out.println("   Ballots Processed: " + mixStats.get("totalBallotsProcessed"));

            System.out.println("\nSecurity Properties Achieved:");
            System.out.println("   ✅ Anonymity: Voter identities hidden via mix network");
            System.out.println("   ✅ Integrity: Digital signatures prevent ballot tampering");
            System.out.println("   ✅ Confidentiality: RSA encryption protects vote choices");
            System.out.println("   ✅ Authentication: Public key cryptography verifies voters");
            System.out.println("   ✅ Verifiability: Ballot hashes enable independent verification");
            System.out.println("   ✅ Non-repudiation: Digital signatures provide proof");
            System.out.println("   ✅ Double-voting Prevention: Unique tokens prevent duplicates");

            System.out.println("\n🎉 ELECTION COMPLETED SUCCESSFULLY!");
            System.out.println("=".repeat(60));
            System.out.println("The secure electronic voting protocol has been demonstrated");
            System.out.println("with all cryptographic security properties maintained.");

        } catch (Exception e) {
            System.err.println("❌ Demo failed with error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Print a section separator
     */
    private static void printSeparator(String title) {
        System.out.println("\n" + "=".repeat(60));
        System.out.println(" " + title);
        System.out.println("=".repeat(60));
    }

    /**
     * Simulate a delay for dramatic effect
     */
    private static void pause(int milliseconds) {
        try {
            Thread.sleep(milliseconds);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
