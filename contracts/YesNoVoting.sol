// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

contract YesNoVoting {
    struct Candidate {
        uint id;
        string name;
        uint yesVotes;
        uint noVotes;
    }

    struct Voter {
        bool hasVoted;
        bool vote;
    }

    address public admin;
    mapping(address => Voter) public voters;
    mapping(uint => Candidate) public candidates;
    uint public candidateCount;
    bool public votingOpen;

    event VoteSubmitted(address voter, uint candidateId, bool vote);
    event VotingStarted();
    event VotingEnded();

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    modifier votingIsOpen() {
        require(votingOpen, "Voting is not open");
        _;
    }

    modifier votingIsNotOpen() {
        require(!votingOpen, "Voting is open");
        _;
    }

    constructor() {
        admin = msg.sender;
        candidateCount = 0;
    }

    function addCandidate(
        string memory _name
    ) public onlyAdmin votingIsNotOpen {
        candidateCount++;
        candidates[candidateCount] = Candidate(candidateCount, _name, 0, 0);
    }

    function getCandidates() public view returns (Candidate[] memory) {
        Candidate[] memory _candidates = new Candidate[](candidateCount);
        for (uint i = 1; i <= candidateCount; i++) {
            _candidates[i - 1] = candidates[i];
        }
        return _candidates;
    }

    function vote(uint _candidateId, bool _vote) public votingIsOpen {
        require(!voters[msg.sender].hasVoted, "Already voted");
        require(
            _candidateId > 0 && _candidateId <= candidateCount,
            "Invalid candidate"
        );

        voters[msg.sender].hasVoted = true;
        voters[msg.sender].vote = _vote;

        if (_vote) {
            candidates[_candidateId].yesVotes++;
        } else {
            candidates[_candidateId].noVotes++;
        }

        emit VoteSubmitted(msg.sender, _candidateId, _vote);
    }

    function startVoting() public onlyAdmin votingIsNotOpen {
        votingOpen = true;
        emit VotingStarted();
    }

    function endVoting() public onlyAdmin votingIsOpen {
        votingOpen = false;
        emit VotingEnded();
    }

    function getCandidateVotes(
        uint _candidateId
    ) public view returns (uint yesVotes, uint noVotes) {
        require(
            _candidateId > 0 && _candidateId <= candidateCount,
            "Invalid candidate"
        );
        return (
            candidates[_candidateId].yesVotes,
            candidates[_candidateId].noVotes
        );
    }
}
