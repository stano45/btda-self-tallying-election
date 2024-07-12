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

    struct Point {
        uint[2] data;
    }

    address public admin;
    Crypto crypto;
    uint minScore;
    uint maxScore;
    mapping (address => uint[2]) public publicKeys; // key
    mapping (address => uint[]) public publicKeysForCandidates; // key
    mapping (uint => Candidate) public candidates;
    mapping (uint => uint) public eachCandidateKeys; //???
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

    function addCandidate(
        string memory _name
    ) public onlyAdmin candidateRegistrationPhase {
        candidateCount++;
        candidates[candidateCount] = Candidate(candidateCount, _name);//, 0, 0);
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

    function registerVoter(uint[2] memory _pubKey, uint[] memory _pubKeyForCandidates) public { // payable??
        require(_pubKeyForCandidates.length == 2 * candidateCount); // 2 because each pub key is point
        voters.push(msg.sender);
        publicKeys[msg.sender] = _pubKey;
        publicKeysForCandidates[msg.sender] = _pubKeyForCandidates;
    }

    function commitVote(uint[] memory commitmentXi, uint[] memory commitmentNu, uint[][] memory proof1, uint[] memory proof2, uint[2] memory W_i) public {
        require(commitmentXi.length == candidateCount);
        require(commitmentNu.length == candidateCount);
        require(proof1.length == candidateCount);
        require(checkZKPoK1(proof1, W_i));
        commitmentsXi[msg.sender] = commitmentXi;
        commitmentsNu[msg.sender] = commitmentNu;
        commitmentsProofs1[msg.sender] = proof1;
        commitmentsProofs2[msg.sender] = proof2;
    }

    function checkZKPoK1(uint[][] memory proof, uint[2] memory W_i) public view returns (bool) {
        ZKPoK1_Proof memory p;
        bool result = true;
        for (uint i = 0; i < candidateCount; i++) {
            uint d_sum = 0;
            p.xi = [proof[i][0], proof[i][1]];
            p.nu = [proof[i][2], proof[i][3]];
            p.c = proof[i][4];
            p.X = proof[i][5];
            p.Y = [proof[i][6], proof[i][7]];
            for (uint j = minScore; j <= maxScore; i++) {
                d_sum = d_sum + proof[i][12 + (j - minScore) * 6];
                result = result && ZKPoK1_Inners(proof[i], j, W_i);
            }
            result = result && (p.c == d_sum); // c = sum d
            result = result && (crypto.Equal(
                p.Y,
                crypto.ecAdd(
                    crypto.ecMul(p.c, publicKeys[msg.sender]),
                    crypto.ecMul(p.X)
                )
            )); // Y = pubKey^c * g^X
        }
        return result;
    }

    function ZKPoK1_Inners(uint[] memory proof, uint j, uint[2] memory W_i) private view returns (bool) {
        bool result = true;
        Point memory a;
        a.data = [proof[8 + (j - minScore) * 6], proof[9 + (j - minScore) * 6]];
        Point memory b;
        b.data = [proof[10 + (j - minScore) * 6], proof[11 + (j - minScore) * 6]];
        Point memory xi;
        xi.data =[proof[0], proof[1]];
        Point memory nu;
        nu.data = [proof[2], proof[3]];
        uint d = proof[12 + (j - minScore) * 6];
        uint e = proof[13 + (j - minScore) * 6];
        result = result && ZKPoK11(xi, a.data, d, e); // a == g^e xi^d
        result = result && ZKPoK12(nu, W_i, b.data, d, e, j); // check that b equals W_i^e * (nu/g^j)^d
        return result;
    }

    function ZKPoK11(Point memory xi, uint[2] memory a, uint d, uint e) private view returns (bool) {
        return crypto.Equal(
            crypto.ecAdd(crypto.ecMul(e), crypto.ecMul(d, xi.data)),
            a
        );
    }

    function ZKPoK12(Point memory nu, uint[2] memory W_i, uint[2] memory b, uint e, uint d, uint j) private view returns (bool) {
        uint[2] memory div = crypto.ecAdd(nu.data, crypto.ecNeg(crypto.ecMul(j)));
        return crypto.Equal(
            crypto.ecAdd(
                crypto.ecMul(e, W_i),
                crypto.ecMul(d, div)),
            b
        );
    }

    function vote(uint[] memory ballotBeta, uint[] memory ballotGamma, BallotProof memory proof) public {
        require(ballotBeta.length == candidateCount);
        require(ballotGamma.length == candidateCount);
        require(proof.p3.length == candidateCount);
        ballotsBeta[msg.sender] = ballotBeta;
        ballotsGamma[msg.sender] = ballotGamma;
        ballotsProofs[msg.sender] = proof;

    }

    function selfTallying() public onlyAdmin {
        require(msg.sender == admin);
//        uint [candidateCount] result; // here we get results
//        return result;
    }
}
