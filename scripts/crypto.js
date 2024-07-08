const EC = require('elliptic').ec;
const secureRandom = require('secure-random')
const BN = require('bn.js');

const abi = require('ethereumjs-abi')
const { keccak256 } = require('ethereumjs-util');
const console = require("node:console");

const group = new EC('p256');

const candidatesNumber = 5;
const votersNumber = 10;
const myNumber = 1; // retrieve somehow
const P = 10;

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
    for (let i = 0; i <= P; i++) {
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
    for (let i = 0; i <= P; i++) {
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
    for (let i = 0; i <= P; i++) {
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

function ZKPoK2(publicKeys, xis, nus, ss) {
    let s_sum = new BN(0)
    let W = getW(publicKeys, myNumber)
    for (let i = 0; i < candidatesNumber; i++) {
        let s = getRand()
        s_sum = s_sum.add(s).mod(group.n)
    }
    let p_xi_new = group.g.mul(s_sum)
    let p_nu_new = W.mul(s_sum)
    let p_xi = group.g.add(group.g.neg())
    let p_nu = group.g.add(group.g.neg())
    for (let i = 0; i < xis.length; i++) {
        p_xi = p_xi.add(xis[i])
    }
    for (let i = 0; i < nus.length; i++) {
        p_nu = p_nu.add(nus[i])
    }
    let data = [
        p_xi.getX(), p_xi.getY(), p_xi_new.getX(), p_xi_new.getY(),
        p_nu.getX(), p_nu.getY(), p_nu_new.getX(), p_nu_new.getY()
    ]
    let input = abi.rawEncode(['uint[8]'],[data])
    let c = new BN(keccak256(input)).mod(group.n)
    let s_ss = new BN(0)
    for (let i = 0; i < ss.length; i++) {
        s_ss = s_ss.add(ss[i])
    }
    let s_s_new = s_sum.sub(c.mul(s_ss)).mod(group.n)
    if (s_s_new.isNeg()) {
        s_s_new = s_s_new.add(group.n)
    }
    return { p_xi, p_xi_new, p_nu, p_nu_new, s_s_new, c }
}

function getW(publicKeys, i) {
    let W_top = group.g.add(group.g.neg())
    let W_bot = group.g.add(group.g.neg())
    for (let j = 0; j < i; j++) {
        W_top = W_top.add(publicKeys[j])
    }
    for (let j = i + 1; j < publicKeys.length; j++) {
        W_bot = W_bot.add(publicKeys[j])
    }
    return W_top.add(W_bot.neg())
}

function commit(privateKey, points, votersPublicKeys) {
    // let A = group.g.add(group.g.neg())
    // for (let i = 0; i < votersPublicKeys.length; i++) {
    //     if (i !== myNumber) {
    //         A = A.add(votersPublicKeys[i]);
    //     }
    // }
    let A = getW(votersPublicKeys, myNumber)
    let ss = []
    let xis = []
    let nus = []
    let C = []
    let W_i = getW(votersPublicKeys, myNumber)
    for (let i = 0; i < candidatesNumber; i++) {
        let s = getRand();
        let xi = group.g.mul(s)
        let nu = group.g.mul(points[i]).add(A.mul(s))
        ss.push(s)
        xis.push(xi)
        nus.push(nu)
        C.push({ xi, nu })
    }
    let pis = []
    for (let i = 0; i < candidatesNumber; i++) {
        let { pi, X_new_new, Y_new } = ZKPoK1(privateKey, ss[i], C[i].xi, C[i].nu, points[i], i, votersPublicKeys);
        pis.push(pi)
        let c = pi[2]

        //check 1
        let p_d = pi[5]
        for (let k = 9; k < pi.length; k+=4) {
            p_d = p_d.add(pi[k]).mod(group.n)
        }
        console.log("ZPK1 test 1 candidate " + i + ": " + c.eq(p_d))

        //check 3
        let check2 = true
        for (let k = 3; k < pi.length; k+=4) {
            let a = pi[k]
            let d = pi[k + 2]
            let e = pi[k + 3]
            let ge = group.g.mul(e)
            let xid = C[i].xi.mul(d)
            check2 = check2 && a.eq(ge.add(xid))
        }
        console.log("ZPK1 test 2 candidate " + i + ": " + check2)

        //check 3
        let check3 = true
        for (let k = 4; k < pi.length; k+=4) {
            let b = pi[k]
            let d = pi[k + 1]
            let e = pi[k + 2]
            let we = W_i.mul(e)
            let nugd = C[i].nu.add(group.g.mul(points[i]).neg()).mul(d)
            check2 = check2 && b.eq(we.add(nugd))
        }
        console.log("ZPK1 test 3 candidate " + i + ": " + check3)

        //check 4
        console.log("ZPK1 test 4 candidate " + i + ": " + Y_new.eq(votersPublicKeys[myNumber].mul(c).add(group.g.mul(X_new_new))))

    }
    let { p_xi, p_xi_new, p_nu, p_nu_new, s_s_new, c } = ZKPoK2(votersPublicKeys, xis, nus, ss)

    //check 1
    let data = [
        p_xi.getX(), p_xi.getY(), p_xi_new.getX(), p_xi_new.getY(),
        p_nu.getX(), p_nu.getY(), p_nu_new.getX(), p_nu_new.getY()
    ]
    let input = abi.rawEncode(['uint[8]'],[data])
    let c2 = new BN(keccak256(input)).mod(group.n)
    console.log("ZKP2 test 1: " + c.eq(c2))

    //check 2
    let a2 = p_xi_new
    let b2 = p_xi.mul(c).add(group.g.mul(s_s_new))
    console.log("ZKP2 test 2: " + a2.eq(b2));

    //check 3
    let a3 = p_nu_new
    let b3_0 = p_nu.add(group.g.mul(P).neg()).mul(c)
    let b3_1 = W_i.mul(s_s_new)
    let b3 = b3_0.add(b3_1)
    console.log("ZKP2 test 3: " + a3.eq(b3));


    return { C, pis }
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

    commit(privateKey, [1, 2, 2, 1, 4], randKeys)
    //now we can publish publicKey and ys on blockchain -- call register



}

main()