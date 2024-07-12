const ScoreVotingContract = artifacts.require("ScoreVoting");
const Crypto = artifacts.require("Crypto");

module.exports = async function (deployer) {
  await deployer.deploy(Crypto);
  const cryptoInstance = await Crypto.deployed();
  await deployer.deploy(ScoreVotingContract, cryptoInstance.address);
};
