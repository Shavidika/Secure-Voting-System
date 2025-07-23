# 🗳️ Secure Electronic Voting Protocol for Class Elections

## Overview

This project implements a cryptographically secure electronic voting system for class elections using Java that ensures:

- ✅ **Anonymity** of the vote
- ✅ **Integrity** of votes
- ✅ **Confidentiality** of voter choice
- ✅ **Authentication** of voters
- ✅ **Verifiable voting** without revealing identities

## 🔐 Protocol Design

### 1. Voter Registration

- Each student registers and receives a unique voter ID
- Public-private key pair generated for each voter using RSA
- Public key submitted to Election Authority (EA)
- Private key kept secret by voter

### 2. Authentication and Ballot Issuing

- EA uses digital signatures to verify voters
- Signed token issued to verified voters (encrypted with their public key)
- Token proves eligibility without revealing voter identity

### 3. Casting the Vote

- Voter prepares ballot with their choice
- Vote encrypted with EA's public key (confidentiality)
- Vote signed with voter's private key (integrity)
- Anonymous submission via mix network

### 4. Vote Collection and Verification

- EA collects encrypted ballots
- Votes decrypted using EA's private key
- Signatures verified for integrity
- Duplicate tokens rejected

### 5. Tallying Votes

- Verified votes are counted
- Tally published with vote hashes and verification proofs
- Allows independent auditing without revealing identities

## 🧰 Cryptographic Tools Used

- **RSA** for asymmetric encryption and digital signatures
- **SHA-256** hashing for verification and transparency
- **Mix networks** for anonymity
- **Secure tokens** to prevent double voting

## 🚀 Getting Started

### Prerequisites

- Java 11 or higher
- (Optional) Maven 3.6+ for dependency management

### Quick Start (Without Maven)

1. **Compile and run using provided scripts:**
   ```cmd
   compile.bat     # Compiles all Java files
   run-demo.bat    # Runs the complete election demonstration
   ```

### With Maven (Recommended)

1. **Compile the project:**

   ```bash
   mvn clean compile
   ```

2. **Run the complete election demonstration:**

   ```bash
   mvn exec:java -Dexec.mainClass="com.voting.demo.VotingDemo"
   ```

3. **Test individual components:**

   ```bash
   # Test cryptographic utilities
   mvn exec:java -Dexec.mainClass="com.voting.crypto.CryptoUtils"

   # Test election authority
   mvn exec:java -Dexec.mainClass="com.voting.core.ElectionAuthority"

   # Test mix network
   mvn exec:java -Dexec.mainClass="com.voting.security.MixNetwork"
   ```

- Maven (for dependency management)
- Bouncy Castle Crypto Library

### Building the Project

```bash
mvn clean compile
```

### Running the Demo

```bash
mvn exec:java -Dexec.mainClass="com.voting.demo.VotingDemo"
```

## 📁 Project Structure

```
├── src/
│   └── main/
│       └── java/
│           └── com/
│               └── voting/
│                   ├── crypto/
│                   │   ├── CryptoUtils.java
│                   │   └── KeyPairManager.java
│                   ├── core/
│                   │   ├── Voter.java
│                   │   ├── ElectionAuthority.java
│                   │   ├── Ballot.java
│                   │   └── VoteToken.java
│                   ├── security/
│                   │   ├── TokenManager.java
│                   │   └── MixNetwork.java
│                   ├── utils/
│                   │   ├── JsonUtils.java
│                   │   └── FileUtils.java
│                   └── demo/
│                       └── VotingDemo.java
├── data/
│   ├── voters/         # Voter data storage
│   ├── ballots/        # Encrypted ballots
│   └── results/        # Election results
├── pom.xml
└── README.md
```

## 🔒 Security Features

- End-to-end RSA encryption (2048-bit keys)
- Digital signature verification
- Anonymous ballot submission via mix network
- Double-voting prevention with secure tokens
- Audit trail with cryptographic proofs
- Zero-knowledge verification

## 📊 Example Usage

Run the demo to see a complete election simulation with multiple voters, candidates, and verification processes.

## 🧪 Testing

```bash
mvn test
```

## 📝 License

This project is for educational purposes in Information Security coursework.
