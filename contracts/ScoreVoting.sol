// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

contract ScoreVoting {
    struct Candidate {
        uint id;
        string name;
    }

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
    mapping (address => uint[2]) public publicKeys; // key + signature
    mapping (uint => Candidate) public candidates;
    mapping (uint => uint) public eachCandidateKeys; //???
    mapping (address => Commitment) public commitments;
    mapping (address => CommitmentProof) public commitmentsProofs; // dual zkp, mb don't save
    mapping (address => Ballot) public ballots;
    mapping (address => BallotProof) public ballotsProofs;
    address[] public voters;

    uint public totalScore;
    uint public candidateCount; // need??

    event VoteSubmitted(address voter, uint candidateId, bool vote);
    event VotingStarted();
    event VotingEnded();


    // 0 - voting not started, 1 - voting started, 2 - voting ended
    uint public votingState;

    constructor() {
        totalScore = 10;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }


    modifier votingIsOpen() {
        require(votingState == 1, "Voting is not open");
        _;
    }

    modifier votingIsNotOpen() {
        require(votingState != 1, "Voting is open");
        _;
    }

    function addCandidate(
        string memory _name
    ) public onlyAdmin votingIsNotOpen {
        candidateCount++;
        candidates[candidateCount] = Candidate(candidateCount, _name, 0, 0);
    }

    function startVoting() public onlyAdmin votingIsNotOpen {
        votingState = 1;
        emit VotingStarted();
    }

    function endVoting() public onlyAdmin votingIsOpen {
        votingState = 2;
        emit VotingEnded();
    }

    function registerVoter(uint[2] memory _pubKey) public payable { // payable??
        voters.push(msg.sender);
        publicKeys[msg.sender] = _pubKey;
    }

    function commitVote(Commitment commitment, CommitmentProof proof) public {
        require(commitment.xi.length == candidateCount);
        require(commitment.nu.length == candidateCount);
        require(proof.p1.length == candidateCount);
        commitments[msg.sender] = commitment;
        commitmentsProofs[msg.sender] = proof;
    }

    function vote(Ballot ballot, BallotProof proof) public {
        require(ballot.beta.length == candidateCount);
        require(ballot.gamma.length == candidateCount);
        require(proof.p3.length == candidateCount);
        ballots[msg.sender] = ballot;
        ballotsProofs[msg.sender] = proof;

    }

    function selfTallying() public onlyAdmin {
        require(msg.sender == admin);
        uint [candidateCount] result; // here we get results
        return result;
    }
}
