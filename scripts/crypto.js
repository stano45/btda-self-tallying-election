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
    let r = getRand()

    let data = [privateKey, candidateId, r]
    let input = abi.rawEncode(['uint[3]'],[data])
    let x = new BN(keccak256(input))
    x = x.mod(group.n)
    let y = group.g.mul(x)
    return { x, y } // x_i -- BigNumber, y_i -- point on elliptic curve
}

function ZKPoK1(privateKey, s, xi, nu, point, j, votersPublicKeys) {
    let newKey = group.genKeyPair()
    let X_new = newKey.getPrivate()
    let Y_new = newKey.getPublic()
    let rho = getRand()
    let W_i = getW(votersPublicKeys, myNumber)
    let es = []
    let ds = []
    let as = []
    let bs = []
    let data = [s, xi.getX(), xi.getY(), nu.getX(), nu.getY()]
    for (let i = 0; i <= 10; i++) {
        let e_k = getRand()
        let d_k = getRand()
        let a_k
        let b_k
        if (i !== point) {
            a_k = group.g.mul(e_k).add(xi.mul(d_k))
            b_k = W_i.mul(e_k).add(nu.add(group.g.mul(point).neg()).mul(d_k))
        } else {
            a_k = group.g.mul(rho)
            b_k = W_i.mul(rho)
        }
        es.push(e_k)
        ds.push(d_k)
        as.push(a_k)
        bs.push(b_k)
        data.push(a_k.getX())
        data.push(a_k.getY())
        data.push(b_k.getX())
        data.push(b_k.getY())
    }
    let input = abi.rawEncode(['uint[49]'],[data])
    let c = new BN(keccak256(input))
    c = c.mod(group.n)
    let dsum = new BN(0)
    for (let i = 0; i <= 10; i++) {
        if (i !== point) {
            dsum = dsum.add(ds[i]).mod(group.n)
        }
    }
    let d_j = c.sub(dsum).mod(group.n)
    if (d_j.isNeg()) {
        d_j = d_j.add(group.n)
    }
    let e_j = rho.sub(s.mul(d_j)).mod(group.n)
    if (e_j.isNeg()) {
        e_j = e_j.add(group.n)
    }
    let X_new_new = X_new.sub(c.mul(privateKey).mod(group.n)).mod(group.n)
    if (X_new_new.isNeg()) {
        X_new_new = X_new_new.add(group.n)
    }
    let pi = [xi, nu, c]
    for (let i = 0; i <= 10; i++) {
        pi.push(as[i])
        pi.push(bs[i])
        if (i !== point) {
            pi.push(ds[i])
            pi.push(es[i])
        } else {
            pi.push(d_j)
            pi.push(e_j)
        }
    }
    return {pi, X_new_new, Y_new}
}

function getW(publicKeys, i) {
    let W_top = group.g.add(group.g.neg())
    let W_bot = group.g.add(group.g.neg())
    for (let j = 0; j < i; j++) {
        W_top = W_top.add(publicKeys[i])
    }
    for (let j = i + 1; j < publicKeys.length; j++) {
        W_bot = W_bot.add(publicKeys[i])
    }
    return W_top.add(W_bot.neg())
}

function commit(privateKey, points, votersPublicKeys, publicKey) {
    let A = group.g.add(group.g.neg())
    for (let i = 0; i < votersPublicKeys.length; i++) {
        A = A.add(votersPublicKeys[i]);
    }
    A = A.add(publicKey.neg())
    let ss = []
    let C = []
    for (let i = 0; i < candidatesNumber; i++) {
        let s = getRand();
        let xi = group.g.mul(s)
        let nu = group.g.mul(points[i]).add(A.mul(s))
        ss.push(s)
        C.push({ xi, nu })
    }
    let pis = []
    for (let i = 0; i < candidatesNumber; i++) {
        let { pi, X_new_new, Y_new } = ZKPoK1(privateKey, ss[i], C[i].xi, C[i].nu, points[i], i, votersPublicKeys);
        let c = pi[2]

        pis.push(pi)
    }
    let pi2 = [] //todo compute using pis
    return { C, pis, pi2 }
}

function main(){
    let { publicKey, privateKey } = keyGen();
    let xs = []
    let ys = []
    // console.log(publicKey)
    for (let i = 1; i <= candidatesNumber; i++) {
        let { x, y } = keyDerive(privateKey, i)
        // console.log(y)
        xs.push(x)
        ys.push(y)
    }
    let randKeys = []
    for (let i = 0; i < votersNumber; i++) {
        if (i !== myNumber) {
            randKeys.push(group.genKeyPair().getPublic())
        } else {
            randKeys.push(publicKey)
        }
    }

    commit(privateKey, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10], randKeys, publicKey)
    //now we can publish publicKey and ys on blockchain -- call register



}

main()