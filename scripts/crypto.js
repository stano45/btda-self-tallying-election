const EC = require('elliptic').ec;
const secureRandom = require('secure-random')
const BN = require('bn.js');

const abi = require('ethereumjs-abi')
const { keccak256 } = require('ethereumjs-util');

const group = new EC('p256');

const candidatesNumber = 5;
const votersNumber = 10;
const myNumber = 1; // retrieve somehow

function keyGen() {
    var key = group.genKeyPair()
    var publicKey = key.getPublic()
    var privateKey = key.getPrivate()
    return { publicKey, privateKey } // publicKey -- point, private -- BN
}

function getRand() {
    const buf = secureRandom.randomBuffer(group.n.bitLength());
    return new BN(buf).mod(group.n);
}

function keyDerive(privateKey, candidateId) {
    r = getRand()

    data = [privateKey,candidateId,r]
    input = abi.rawEncode(['uint[3]'],[data])
    x = new BN(keccak256(input))
    x = x.mod(group.n)
    y = group.g.mul(x)
    return { x, y } // x_i -- BigNumber, y_i -- point on elliptic curve
}

function ZKPoK(privateKey, xi, nu) {
    let w = getRand()
    let r = getRand()
    let d = getRand()
    let a = group.g.mul(r).add(xi.mul(d))
    //todo correct proof
    return a
}

function commit(privateKey, points, votersPublicKeys, publicKey) {
    commitments = []
    let A = group.g.add(group.g.neg())
    for (let i = 0; i < votersPublicKeys.length; i++) {
        A = A.add(votersPublicKeys[i]);
    }
    A = A.add(publicKey.neg())
    let C = []
    for (let i = 0; i < candidatesNumber; i++) {
        let s = getRand();
        let xi = group.g.mul(s)
        let nu = group.g.mul(points[i]).add(A.mul(s))
        C.push({ xi, nu })
    }
    let pis = []
    for (let i = 0; i < candidatesNumber; i++) {
        let pi = ZKPoK(privateKey, C[i].xi, C[i].nu);
        pis.push(pi)
    }
    let pi2 = [] //todo compute using pis
    return { C, pis, pi2 }
}

function main(){
    let { publicKey, privateKey } = keyGen();
    let xs = []
    let ys = []
    console.log(publicKey)
    for (let i = 1; i <= candidatesNumber; i++) {
        let { x, y } = keyDerive(privateKey, i)
        // console.log(y)
        xs.push(x)
        ys.push(y)
    }

    //now we can publish publicKey and ys on blockchain -- call register



}

main()