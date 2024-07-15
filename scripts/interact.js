const ScoreVoting = artifacts.require("ScoreVoting");
const { keyGen, keyDerive, commit, getW, vote } = require("./crypto.js");

module.exports = async function(callback) {
    try {
        const accounts = await web3.eth.getAccounts();
        const instance = await ScoreVoting.deployed();

        // Add candidates (account 0 is admin account)
        await instance.addCandidate("Candidate 1", { from: accounts[0] });
        await instance.addCandidate("Candidate 2", { from: accounts[0] });
        await instance.addCandidate("Candidate 3", { from: accounts[0] });
        await instance.addCandidate("Candidate 4", { from: accounts[0] });
        await instance.addCandidate("Candidate 5", { from: accounts[0] });

        await instance.startVotersRegistration()
        let keys = []
        let pubKeys = []
        let votingPublicKeys = []
        let votingPrivateKeys = []
        let votingKeys = []

        for (let i = 1; i < accounts.length; i++) {
            let key = keyGen();
            keys.push(key);
            pubKeys.push(key.publicKey);
            let toPass = []
            let toPass2 = []
            let toPass3 = []
            let votingKey = []
            for (let j = 0; j < 5; j++) {
                let otherKeys = keyDerive(key.privateKey, j)
                toPass.push(otherKeys.y.getX());
                toPass.push(otherKeys.y.getY());
                toPass2.push(otherKeys.y);
                toPass3.push(otherKeys.x);
            }
            votingKeys.push(votingKey)
            votingPublicKeys.push(toPass2)
            votingPrivateKeys.push(toPass3)
            await instance.registerVoter(
                [key.publicKey.getX(), key.publicKey.getY()],
                 toPass, { from: accounts[i] });
        }

        let Cs = []
        let sss = []

        const ks = await instance.getVoterPublicKeys()
        console.log(ks)

        const voters = await instance.getVoters()
        console.log(voters)

        for (let i = 1; i < accounts.length; i++) {
            // console.log(votingPublicKeys[i - 1].length)
            let { C, pis, ss, pi2 } = commit(keys[i - 1].privateKey, [2, 1, 2, 4, 1], pubKeys, i - 1)
            Cs.push(C)
            sss.push(ss)
            let xis = []
            let nus = []
            for (let j = 0; j < C.length; j++) {
                xis.push(C[j].xi.getX())
                xis.push(C[j].xi.getY())
                nus.push(C[j].nu.getX())
                nus.push(C[j].nu.getY())
            }
            let W_i = getW(pubKeys, i - 1)
            await instance.commitVote(xis, nus, pis, pi2, [W_i.getX(), W_i.getY()], { from: accounts[i] });
        }

        for (let i = 1; i < accounts.length; i++) {
            let { B, pi3s, } = vote(keys[i - 1].privateKey, [2, 1, 2, 4, 1], pubKeys,
                votingPrivateKeys[i - 1], votingPublicKeys, Cs[i - 1], sss[i - 1], i - 1)
            let betas = []
            let gammas = []
            for (let j = 0; j < B.length; j++) {
                betas.push(B[j].beta.getX())
                betas.push(B[j].beta.getY())
                gammas.push(B[j].gamma.getX())
                gammas.push(B[j].gamma.getY())
            }

            let W_i = getW(pubKeys, i - 1)
            await instance.vote(betas, gammas, pi3s, [], [W_i.getX(), W_i.getY()],
                { from: accounts[i] });
        }

        callback();
    } catch (error) {
        console.error(error);
        callback(error);
    }
};
