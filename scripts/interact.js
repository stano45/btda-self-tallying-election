const YesNoVoting = artifacts.require("YesNoVoting");

module.exports = async function(callback) {
    try {
        const accounts = await web3.eth.getAccounts();
        const instance = await YesNoVoting.deployed();

        // Add candidates (account 0 is admin account)
        await instance.addCandidate("Candidate 1", { from: accounts[0] });
        await instance.addCandidate("Candidate 2", { from: accounts[0] });
        await instance.addCandidate("Candidate 3", { from: accounts[0] });

        // Perform voting
        await instance.vote(1, true, { from: accounts[1] });
        await instance.vote(2, false, { from: accounts[2] });
        await instance.vote(1, true, { from: accounts[3] });
        await instance.vote(2, true, { from: accounts[4] });
        await instance.vote(1, false, { from: accounts[5] });

        // Check votes
        let result = await instance.getCandidateVotes(1);
        console.log("Candidate 1 - Yes Votes: " + result[0].toString() + ", No Votes: " + result[1].toString());

        result = await instance.getCandidateVotes(2);
        console.log("Candidate 2 - Yes Votes: " + result[0].toString() + ", No Votes: " + result[1].toString());

        // End voting
        await instance.endVoting({ from: accounts[0] });

        callback();
    } catch (error) {
        console.error(error);
        callback(error);
    }
};
