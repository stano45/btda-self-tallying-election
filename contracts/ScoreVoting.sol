// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import './Crypto.sol';

contract ScoreVoting {
    struct Candidate {
        uint id;
        string name;
    }

//    struct PublicKeys {
//        uint pubKey;
//        uint[] pubKeysForCandidates;
//    }

    struct CommitmentProof {
        uint[][] p1;
        uint[] p2;
    }

    struct BallotProof {
        uint[] p3;
        uint p4;
    }

    struct Commitment {
        uint[] xi;
        uint[] nu;
    }

    struct Ballot {
        uint[] beta;
        uint[] gamma;
    }

    struct ZKPoK1_Proof {
        uint[2] xi;
        uint[2] nu;
        uint c;
        uint[2] Y;
        uint X;
        uint[] other;
    }

    struct ZKPoK1_Proof_API {
        uint[] xis;
        uint[] nus;
        uint[][] proof;
        uint[2] W_i;
        uint candidateCount;
        uint minScore;
        uint maxScore;
        uint[2] publicKey;
    }

    struct ZKPoK2_Proof {
        uint[2] xi;
        uint[2] xi_new;
        uint[2] nu;
        uint[2] nu_new;
        uint s_s_new;
        uint c;
    }

    struct ZKPoK3_Proof_API {
        uint[] betas;
        uint[] gammas;
        uint[][] proof;
        uint[2] W_i;
        uint candidateCount;
        uint minScore;
        uint maxScore;
        uint[] xis;
        uint[] nus;
        uint[] publicKeysForCandidates;
        uint[2] publicKey;
        uint[] Zs;
    }

//    struct ZKPoK3_2_Proof_API {
//        uint[] betas;
//        uint[] gammas;
//        uint[][] proof;
//        uint[2] W_i;
//        uint candidateCount;
//        uint minScore;
//        uint maxScore;
//        uint[] xis;
//        uint[] nus;
//        uint[2] publicKey;
//        uint[] Zs;
//    }

    struct ZKPoK3_Proof {
        uint[2] xi;
        uint[2] nu;
        uint[2] beta;
        uint[2] gamma;
        uint c;
        uint[2] y;
        uint[2] y_new;
        uint[2] beta_new;
        uint X_new;
        uint x_new;
        uint r_new;
    }

    struct ZKPoK3_Proof_Point {
        uint[2] a;
        uint[2] a_prime;
        uint[2] b;
        uint[2] b_prime;
        uint d;
        uint e;
        uint d_prime;
        uint e_prime;
        uint f_prime;
    }

    struct Point {
        uint[2] data;
    }

    address public admin;
    Crypto crypto;
    uint minScore;
    uint maxScore;
    mapping (address => uint[2]) public publicKeys; // key
    mapping (address => uint[]) public publicKeysForCandidates; // key
    uint[][] public publicKeysForCandidates2;
    mapping (uint => Candidate) public candidates;
    mapping (address => uint[]) public commitmentsXi;
    mapping (address => uint[]) public commitmentsNu;
    mapping (address => uint[][]) public commitmentsProofs1; // dual zkp
    mapping (address => uint[]) public commitmentsProofs2; // dual zkp
    mapping (address => uint[]) public ballotsBeta;
    mapping (address => uint[]) public ballotsGamma;
    mapping (address => BallotProof) public ballotsProofs;
    address[] public voters;

    uint public totalScore;
    uint public candidateCount; // need??

    event VoteSubmitted(address voter, uint candidateId, bool vote);
    event VotersRegistrationStarted();
    event VotingStarted();
    event VotingEnded();


    // 0 - candidates registration
    // 1 - voters registration
    // 2 - commit phase
    // 3 - vote phase
    // 4 - vote ended
    uint public votingState;

    constructor(address _cryptoAddress) {
        admin = msg.sender;
        votingState = 0;
        totalScore = 10;
        minScore = 0;
        maxScore = 5;
        crypto = Crypto(_cryptoAddress);
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }


    modifier candidateRegistrationPhase() {
        require(votingState == 0, "Candidate registration phase ended");
        _;
    }

    modifier votersRegistrationPhase() {
        require(votingState == 1, "Voters registration phase ended");
        _;
    }

    modifier commitPhase() {
        require(votingState == 2, "Commit phase ended");
        _;
    }

    modifier votePhase() {
        require(votingState == 3, "Vote phase ended");
        _;
    }

    modifier voteEnded() {
        require(votingState == 4, "Vote ended");
        _;
    }

    function getVotingStatus() public view returns (uint) {
        return votingState;
    }

    function addCandidate(
        string memory _name
    ) public onlyAdmin candidateRegistrationPhase {
        candidateCount++;
        candidates[candidateCount] = Candidate(candidateCount, _name);//, 0, 0);
    }

    function getCandidates() public view returns (Candidate[] memory) {
        Candidate[] memory _candidates = new Candidate[](candidateCount);
        for (uint i = 1; i <= candidateCount; i++) {
            _candidates[i - 1] = candidates[i];
        }
        return _candidates;
    }

    function startVotersRegistration() public onlyAdmin candidateRegistrationPhase {
        votingState = 1;
        emit VotersRegistrationStarted();
    }

    function startVoting() public onlyAdmin votersRegistrationPhase {
        votingState = 3;
        emit VotingStarted();
    }

    function endVoting() public onlyAdmin votePhase {
        votingState = 4;
        emit VotingEnded();
    }

    function getVoterPublicKeys() public view returns (uint[2][] memory allPubKeys) {
        uint voterCount = voters.length;
        allPubKeys = new uint[2][](voterCount);

        for (uint i = 0; i < voterCount; i++) {
            address voter = voters[i];
            allPubKeys[i] = publicKeys[voter];
        }

        return allPubKeys;
    }

    function registerVoter(uint[2] memory _pubKey, uint[] memory _pubKeyForCandidates) public { // payable??
        require(_pubKeyForCandidates.length == 2 * candidateCount); // 2 because each pub key is point
        voters.push(msg.sender);
        publicKeys[msg.sender] = _pubKey;
        publicKeysForCandidates[msg.sender] = _pubKeyForCandidates;
        publicKeysForCandidates2.push(_pubKeyForCandidates);
    }

    function getVoters() public view returns (address[] memory) {
        return voters;
    }

    function commitVote(uint[] memory commitmentXi, uint[] memory commitmentNu, uint[][] memory proof1, uint[] memory proof2, uint[2] memory W_i) public {
        require(commitmentXi.length == candidateCount * 2, "Wrong xis");
        require(commitmentNu.length == candidateCount * 2, "Wrong nus");
        require(proof1.length == candidateCount, "Wrong proof1");

        ZKPoK1_Proof_API memory p1;
        p1.xis = commitmentXi;
        p1.nus = commitmentNu;
        p1.proof = proof1;
        p1.W_i = W_i;
        p1.candidateCount = candidateCount;
        p1.minScore = minScore;
        p1.maxScore = maxScore;
        p1.publicKey = publicKeys[msg.sender];
        require(crypto.checkZKPoK1(p1), "Wrong ZKPoK1");

        require(crypto.checkZKPoK2(proof2, W_i, totalScore), "Wrong ZKPoK2");
        commitmentsXi[msg.sender] = commitmentXi;
        commitmentsNu[msg.sender] = commitmentNu;
        commitmentsProofs1[msg.sender] = proof1;
        commitmentsProofs2[msg.sender] = proof2;
    }

    function vote(uint[] memory betas, uint[] memory gammas, uint[][] memory proof3, uint[] memory proof4, uint[2] memory W_i) public {
        require(betas.length == candidateCount * 2, "Wrong betas");
        require(gammas.length == candidateCount * 2, "Wrong gammas");
        require(proof3.length == candidateCount, "Wrong proof3");
        require(proof3[0].length == 8 + (maxScore - minScore + 1) * 13, "Wrong proof3");

        ZKPoK3_Proof_API memory p;
        p.betas = betas;
        p.gammas = gammas;
        p.proof = proof3;
        p.W_i = W_i;
        p.candidateCount = candidateCount;
        p.minScore = minScore;
        p.maxScore = maxScore;
        p.xis = commitmentsXi[msg.sender];
        p.nus = commitmentsNu[msg.sender];
        p.publicKeysForCandidates = publicKeysForCandidates[msg.sender];
        p.publicKey = publicKeys[msg.sender];
        p.Zs = new uint[](candidateCount * 2);
        for (uint i = 0; i < candidateCount; i++) {
            uint[] memory Zs = new uint[](voters.length * 2);
            uint num = 1000;
            uint j = 0;
            for (j = 0; j < voters.length; j++) {
                Zs[j * 2] = publicKeysForCandidates[voters[j]][i * 2];
                Zs[j * 2 + 1] = publicKeysForCandidates[voters[j]][i * 2 + 1];
                if (msg.sender == voters[j]) {
                    num = j;
                }
            }
            uint[2] memory z = getWi(Zs, num);
            p.Zs[i * 2] = z[0];
            p.Zs[i * 2 + 1] = z[1];
        }

        require(crypto.checkZKPoK3_1(p), "Wrong ZKPoK3");
        require(crypto.checkZKPoK3_2(p), "Wrong ZKPoK3");

        ballotsBeta[msg.sender] = betas;
        ballotsGamma[msg.sender] = gammas;
//        ballotsProofs[msg.sender] = proof;

    }

    function getAllBetas() public view returns (uint[][] memory allBetas) {
        uint voterCount = voters.length;
        allBetas = new uint[][](voterCount);

        for (uint i = 0; i < voterCount; i++) {
            address voter = voters[i];
            allBetas[i] = ballotsBeta[voter];
        }

        return allBetas;
    }

    function getAllGammas() public view returns (uint[][] memory allGammas) {
        uint voterCount = voters.length;
        allGammas = new uint[][](voterCount);

        for (uint i = 0; i < voterCount; i++) {
            address voter = voters[i];
            allGammas[i] = ballotsGamma[voter];
        }

        return allGammas;
    }

    function getWi(uint[] memory keys, uint i) private view returns (uint[2] memory) {
        uint[2] memory W_top = crypto.ecMul(0);
        uint[2] memory W_bot = crypto.ecMul(0);
        for (uint j = 0; j < i * 2; j+=2) {
            W_top = crypto.ecAdd(W_top, [keys[j], keys[j + 1]]);
        }
        for (uint j = i * 2 + 2; j < keys.length; j+=2) {
            W_bot = crypto.ecAdd(W_bot, [keys[j], keys[j + 1]]);
        }
        return crypto.ecAdd(W_top, crypto.ecNeg(W_bot));
    }

    function selfTallying() public onlyAdmin {
        require(msg.sender == admin);
//        uint [candidateCount] result; // here we get results
//        return result;
    }
}
