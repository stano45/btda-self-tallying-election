const SimpleContract = artifacts.require("ScoreVoting");

module.exports = function (deployer) {
    deployer.deploy(SimpleContract);
};
