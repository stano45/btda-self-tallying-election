// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

contract ScoreVoting {
    struct Candidate {
        uint id;
        string name;
        uint score;
    }

    struct Voter {
        bool hasVoted;
        mapping(uint => uint) scores; // candidateId => score
    }

    address public admin;
    mapping(address => Voter) public voters;
    mapping(uint => Candidate) public candidates;
    uint public candidateCount;
    bool public votingOpen;

    event VoteSubmitted(address voter, uint candidateId, uint score);
    event VotingEnded();

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    modifier votingIsOpen() {
        require(votingOpen, "Voting is not open");
        _;
    }

    constructor() {
        admin = msg.sender;
        votingOpen = true;
        candidateCount = 0; // Ensure candidateCount is initialized to 0
    }

    function addCandidate(string memory _name) public onlyAdmin {
        candidateCount++;
        candidates[candidateCount] = Candidate(candidateCount, _name, 0);
    }

    function registerVoter(address _voter) public onlyAdmin {
        require(!voters[_voter].hasVoted, "Voter already registered");
        // Initialize Voter struct (no need to set hasVoted again here)
    }

    function vote(uint _candidateId, uint _score) public votingIsOpen {
        require(!voters[msg.sender].hasVoted, "Already voted");
        require(
            _candidateId > 0 && _candidateId <= candidateCount,
            "Invalid candidate"
        );

        voters[msg.sender].hasVoted = true;
        voters[msg.sender].scores[_candidateId] = _score;
        candidates[_candidateId].score += _score;

        emit VoteSubmitted(msg.sender, _candidateId, _score);
    }

    function endVoting() public onlyAdmin {
        votingOpen = false;
        emit VotingEnded();
    }

    function getCandidateScore(uint _candidateId) public view returns (uint) {
        require(
            _candidateId > 0 && _candidateId <= candidateCount,
            "Invalid candidate"
        );
        return candidates[_candidateId].score;
    }
}
