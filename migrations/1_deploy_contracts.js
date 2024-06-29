const SimpleContract = artifacts.require("YesNoVoting");

module.exports = function (deployer) {
    deployer.deploy(SimpleContract);
};
