// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

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
        uint[] p1;
        uint p2;
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

    address public admin;
    mapping (address => uint) public publicKeys; // key
    mapping (address => uint[]) public publicKeysForCandidates; // key
    mapping (uint => Candidate) public candidates;
    mapping (uint => uint) public eachCandidateKeys; //???
    mapping (address => uint[]) public commitmentsXi;
    mapping (address => uint[]) public commitmentsNu;
    mapping (address => CommitmentProof) public commitmentsProofs; // dual zkp, mb don't save
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

    constructor() {
        totalScore = 10;
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

    function registerVoter(uint _pubKey, uint[] memory _pubKeyForCandidates) public payable { // payable??
        voters.push(msg.sender);
        publicKeys[msg.sender] = _pubKey;
        publicKeysForCandidates[msg.sender] = _pubKeyForCandidates;
    }

    function commitVote(uint[] memory commitmentXi, uint[] memory commitmentNu, CommitmentProof memory proof) public {
        require(commitmentXi.length == candidateCount);
        require(commitmentNu.length == candidateCount);
        require(proof.p1.length == candidateCount);
        commitmentsXi[msg.sender] = commitmentXi;
        commitmentsNu[msg.sender] = commitmentNu;
        commitmentsProofs[msg.sender] = proof;
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
