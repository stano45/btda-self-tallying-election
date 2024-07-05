const SimpleContract = artifacts.require("YesNoVoting");
const ScoreVotingContract = artifacts.require("ScoreVoting");

module.exports = function (deployer) {
    deployer.deploy(SimpleContract);
    deployer.deploy(ScoreVotingContract);
};
