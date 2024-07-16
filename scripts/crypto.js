const EC = require('elliptic').ec;
const secureRandom = require('secure-random')
const BN = require('bn.js');

const abi = require('ethereumjs-abi')
const { keccak256 } = require('ethereumjs-util');
const console = require("node:console");

const group = new EC('bn256');

const candidatesNumber = 5;
const votersNumber = 9;
const myNumber = 3; // retrieve somehow
const P = 10;
const maxScore = 5;
const minScore = 0;

function keyGen() {
    let key = group.genKeyPair()
    let publicKey = key.getPublic()
    let privateKey = key.getPrivate()
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

function ZKPoK1(privateKey, s, xi, nu, point, j, votersPublicKeys, number) {
    let newKey = group.genKeyPair()
    let X_new = newKey.getPrivate()
    let Y_new = newKey.getPublic()
    let rho = getRand()
    let W_i = getW(votersPublicKeys, number)
    let es = []
    let ds = []
    let as = []
    let bs = []
    let data = [s, xi.getX(), xi.getY(), nu.getX(), nu.getY()]
    for (let i = minScore; i <= maxScore; i++) {
        let e_k = getRand()
        let d_k = getRand()
        let a_k
        let b_k
        if (i !== point) {
            a_k = group.g.mul(e_k).add(xi.mul(d_k))
            b_k = W_i.mul(e_k).add(nu.add(group.g.mul(i).neg()).mul(d_k))
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
    let inputSize = (maxScore - minScore + 1) * 4 + 5
    let input = abi.rawEncode([`uint[${inputSize}]`],[data])
    let c = new BN(keccak256(input))
    c = c.mod(group.n)
    let dsum = new BN(0)
    for (let i = minScore; i <= maxScore; i++) {
        if (i !== point) {
            dsum = dsum.add(ds[i - minScore]).mod(group.n)
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
    let pi = [c, X_new_new, Y_new.getX(), Y_new.getY()]
    for (let i = minScore; i <= maxScore; i++) {
        pi.push(as[i - minScore].getX())
        pi.push(as[i - minScore].getY())
        pi.push(bs[i - minScore].getX())
        pi.push(bs[i - minScore].getY())
        if (i !== point) {
            pi.push(ds[i - minScore])
            pi.push(es[i - minScore])
        } else {
            pi.push(d_j)
            pi.push(e_j)
        }
    }
    return {pi}
}

function ZKPoK2(publicKeys, xis, nus, ss, number) {
    let s_sum = new BN(0)
    let W = getW(publicKeys, number)
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
    let c = new BN(keccak256(input))//.mod(group.n)
    let s_ss = new BN(0)
    for (let i = 0; i < ss.length; i++) {
        s_ss = s_ss.add(ss[i])
    }
    let s_s_new = s_sum.sub(c.mul(s_ss)).mod(group.n)
    if (s_s_new.isNeg()) {
        s_s_new = s_s_new.add(group.n)
    }
    return [
        p_xi.getX(), p_xi.getY(), p_xi_new.getX(), p_xi_new.getY(),
        p_nu.getX(), p_nu.getY(), p_nu_new.getX(), p_nu_new.getY(),
        s_s_new, c
    ]
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

function commit(privateKey, points, votersPublicKeys, number) {
    // let A = group.g.add(group.g.neg())
    // for (let i = 0; i < votersPublicKeys.length; i++) {
    //     if (i !== myNumber) {
    //         A = A.add(votersPublicKeys[i]);
    //     }
    // }
    let A = getW(votersPublicKeys, number)
    let ss = []
    let xis = []
    let nus = []
    let C = []
    let W_i = getW(votersPublicKeys, number)
    for (let i = 0; i < candidatesNumber; i++) {
        let s = getRand();
        let xi = group.g.mul(s)
        let nu = group.g.mul(points[i]).add(A.mul(s))
        ss.push(s)
        xis.push(xi)
        nus.push(nu)
        C.push({ xi, nu })
        // console.log(C[i])
    }
    let pis = []
    for (let i = 0; i < candidatesNumber; i++) {
        let { pi } = ZKPoK1(privateKey, ss[i], C[i].xi, C[i].nu, points[i], i, votersPublicKeys, number);
        pis.push(pi)
        let c = pi[0]
        let X_new_new = pi[1]
        let Y_new = group.curve.point(pi[2], pi[3])
        //
        //check 1
        // let p_d = pi[7]
        // for (let k = 11; k < pi.length; k+=4) {
        //     p_d = p_d.add(pi[k]).mod(group.n)
        // }
        // console.log("ZPK1 test 1 candidate " + i + ": " + c.eq(p_d))

        // //check 3
        // let check2 = true
        // for (let k = 5; k < pi.length; k+=4) {
        //     let a = pi[k]
        //     let d = pi[k + 2]
        //     let e = pi[k + 3]
        //     let ge = group.g.mul(e)
        //     let xid = C[i].xi.mul(d)
        //     check2 = check2 && a.eq(ge.add(xid))
        // }
        // console.log("ZPK1 test 2 candidate " + i + ": " + check2)
        //
        // //check 3
        let check3 = true
        for (let k = 6; k < pi.length; k+=6) {
            let b = group.curve.point(pi[k], pi[k + 1])
            let d = pi[k + 2]
            let e = pi[k + 3]
            let we = W_i.mul(e)
            let pointValue =  Math.floor((k - 6) / 6)
            let nugd = C[i].nu.add(group.g.mul(pointValue).neg()).mul(d)
            check3 = check3 && b.eq(we.add(nugd))
        }
        console.log("ZPK1 test 3 candidate " + i + ": " + check3)
        //
        //check 4
        // console.log("Check priv pub: " + votersPublicKeys[number].eq(group.g.mul(privateKey)))
        console.log("ZPK1 test 4 candidate " + i + ": " + Y_new.eq(votersPublicKeys[number].mul(c).add(group.g.mul(X_new_new))))

    }
    let pi2 = ZKPoK2(votersPublicKeys, xis, nus, ss, number)
    //check 1
    let p_xi = group.curve.point(pi2[0], pi2[1])
    let p_xi_new = group.curve.point(pi2[2], pi2[3])
    let p_nu = group.curve.point(pi2[4], pi2[5])
    let p_nu_new = group.curve.point(pi2[6], pi2[7])
    let s_s_new = pi2[8]
    let c = pi2[9]
    let res = { p_xi, p_xi_new, p_nu, p_nu_new, s_s_new, c }
    let data = [
        pi2[0], pi2[1], pi2[2], pi2[3],
        pi2[4], pi2[5], pi2[6], pi2[7]
    ]
    let input = abi.rawEncode(['uint[8]'],[data])
    let c2 = new BN(keccak256(input))//.mod(group.n)
    console.log("ZKP2 test 1: " + pi2[9].eq(c2))

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

    return { C, pis, ss, pi2 }
}

function ZKPoK3(privateKey, votersPublicKeys, point, xi, nu, beta, gamma, Z_i, s, x, y, r, number) {
    let W_i = getW(votersPublicKeys, number)
    let as = []
    let bs = []
    let ds = []
    let es = []
    let a_primes = []
    let b_primes = []
    let d_primes = []
    let e_primes = []
    let f_primes = []
    let rho = getRand()
    for (let k = minScore; k <= maxScore; k++) {
        let a
        let b
        let a_prime
        let b_prime
        let e, d, e_prime, d_prime, f_prime
        if (k === point) {
            e = d = e_prime = d_prime = f_prime = new BN(0)
            a = group.g.mul(rho)
            b = W_i.mul(rho)
            a_prime = group.g.mul(rho)
            b_prime = W_i.add(group.g).mul(rho)
        } else {
            e = getRand()
            e_prime = getRand()
            d = getRand()
            d_prime = getRand()
            f_prime = getRand()
            a = group.g.mul(e).add(xi.mul(d))
            b = W_i.mul(e).add(nu.add(group.g.mul(k).neg()).mul(d))
            a_prime = group.g.mul(e_prime).add(votersPublicKeys[number].mul(d_prime))
            b_prime = W_i.mul(e_prime).add(group.g.mul(f_prime)).add(gamma.add(group.g.mul(k).neg()).mul(d_prime))
        }
        as.push(a)
        bs.push(b)
        ds.push(d)
        es.push(e)
        a_primes.push(a_prime)
        b_primes.push(b_prime)
        d_primes.push(d_prime)
        e_primes.push(e_prime)
        f_primes.push(f_prime)
    }

    let X_new = getRand()
    let x_new = getRand()
    let r_new = getRand()
    let y_new = group.g.mul(x_new)
    let beta_new = Z_i.mul(x_new).add(group.g.mul(r_new))
    let data = [
        // privateKey, s, xi.getX(), xi.getY(), nu.getX(), nu.getY(),
        xi.getX(), xi.getY(), nu.getX(), nu.getY(),
        gamma.getX(), gamma.getY(), y.getX(), y.getY(), y_new.getX(), y_new.getY(),
        beta.getX(), beta.getY(), beta_new.getX(), beta_new.getY()]
    let dataSize = 14
    for (let k = minScore; k <= maxScore; k++) {
        data.push(as[k - minScore].getX())
        data.push(as[k - minScore].getY())
        data.push(bs[k - minScore].getX())
        data.push(bs[k - minScore].getY())
        data.push(a_primes[k - minScore].getX())
        data.push(a_primes[k - minScore].getY())
        data.push(b_primes[k - minScore].getX())
        data.push(b_primes[k - minScore].getY())
        dataSize += 8
    }
    let input = abi.rawEncode([`uint[${dataSize}]`],[data])
    let c = new BN(keccak256(input)).mod(group.n)
    let X_new_new = toPos(X_new.sub(c.mul(privateKey)).mod(group.n))
    let x_new_new = toPos(x_new.sub(c.mul(x)).mod(group.n))
    let r_new_new = toPos(r_new.sub(c.mul(r)).mod(group.n))
    let d_s = new BN(0)
    let d_s_prime = new BN(0)
    for (let k = minScore; k <= maxScore; k++) {
        if (k === point) {
            continue
        }
        d_s = d_s.add(ds[k]).mod(group.n)
        d_s_prime = d_s_prime.add(d_primes[k]).mod(group.n)
    }
    let d_j = toPos(c.sub(d_s))
    let e_j = toPos(rho.sub(s.mul(d_j)).mod(group.n))
    let d_j_prime = toPos(c.sub(d_s_prime).mod(group.n))
    let e_j_prime = toPos(rho.sub(privateKey.mul(d_j_prime)).mod(group.n))
    let f_j_prime = toPos(rho.sub(r.mul(d_j_prime)).mod(group.n))

    // let pi3 = [
    //     xi, nu, gamma, c, y, y_new, beta, beta_new, X_new_new,
    //     x_new_new, r_new_new
    // ]
    let pi3 = [
        c, y_new.getX(), y_new.getY(), beta_new.getX(), beta_new.getY(), X_new_new,
        x_new_new, r_new_new
    ]
    for (let i = minScore; i <= maxScore; i++) {
        if (i !== point) {
            pi3.push(as[i - minScore].getX())
            pi3.push(as[i - minScore].getY())
            pi3.push(bs[i - minScore].getX())
            pi3.push(bs[i - minScore].getY())
            pi3.push(ds[i - minScore])
            pi3.push(es[i - minScore])
            pi3.push(a_primes[i - minScore].getX())
            pi3.push(a_primes[i - minScore].getY())
            pi3.push(b_primes[i - minScore].getX())
            pi3.push(b_primes[i - minScore].getY())
            pi3.push(d_primes[i - minScore])
            pi3.push(e_primes[i - minScore])
            pi3.push(f_primes[i - minScore])
        } else {
            pi3.push(as[i - minScore].getX())
            pi3.push(as[i - minScore].getY())
            pi3.push(bs[i - minScore].getX())
            pi3.push(bs[i - minScore].getY())
            pi3.push(d_j)
            pi3.push(e_j)
            pi3.push(a_primes[i - minScore].getX())
            pi3.push(a_primes[i - minScore].getY())
            pi3.push(b_primes[i - minScore].getX())
            pi3.push(b_primes[i - minScore].getY())
            pi3.push(d_j_prime)
            pi3.push(e_j_prime)
            pi3.push(f_j_prime)
        }
    }

    return pi3

}

function ZKPoK4(privateKey, publicKeys, p_gamma, number) {
    let X_new = getRand()
    let Y_new = group.g.mul(X_new)
    let W_i = getW(publicKeys, number)
    let gamma_new = W_i.mul(X_new.mul(new BN(candidatesNumber)).mod(group.n))
    let Y = publicKeys[number]
    let data = [Y.getX(), Y.getY(), Y_new.getX(), Y_new.getY(), p_gamma.getX(), p_gamma.getY(), gamma_new.getX(), gamma_new.getY()]
    let input = abi.rawEncode(['uint[8]'], [data])
    let c = new BN(keccak256(input)).mod(group.n)
    let X_new_new = toPos(X_new.sub(c.mul(privateKey)).mod(group.n))
    return { Y, Y_new, X_new_new, p_gamma, gamma_new, c }

}

function vote(privateKey, points, votersPublicKeys, xs, votersYs, C, ss, number) {
    let Z = []
    let rs = []
    let W_i = getW(votersPublicKeys, number)
    let B = []
    let p_gamma_ = group.g.add(group.g.neg())
    let p_betas = group.g.add(group.g.neg())
    let check = group.g.add(group.g.neg())
    for (let j = 0; j < candidatesNumber; j++) {
        let yj = []
        for (let k = 0; k < votersYs.length; k++) {
            yj.push(votersYs[k][j])
        }
        let Z_i = getW(yj, number)
        let r = getRand()
        let beta = Z_i.mul(xs[j]).add(group.g.mul(r))
        let gamma = group.g.mul(points[j]).add(W_i.mul(privateKey)).add(group.g.mul(r))
        B.push({ beta, gamma })
        rs.push(r)
        Z.push(Z_i)
        p_gamma_ = p_gamma_.add(gamma)
        //Todo check again, doesn't work now
        check = check.add(Z_i.mul(xs[j]))
        p_betas = p_betas.add(beta)
        // p_betas = p_betas.add(gamma.add(group.g.mul(P).add(p_beta)).neg())
    }
    let cd = check.eq(group.g.add(group.g.neg()))
    let pi3s = []
    for (let j = 0; j < candidatesNumber; j++) {
        let pi3 = ZKPoK3(
            privateKey, votersPublicKeys, points[j], C[j].xi, C[j].nu, B[j].beta, B[j].gamma,
            Z[j], ss[j], xs[j], votersYs[number][j], rs[j], number
        )
        pi3s.push(pi3)
        // let c = pi3[3]
        // //check 1
        //
        // //check 2
        // let d_sum = new BN(0)
        // let d_prime_sum = new BN(0)
        // for (let k = 13; k < pi3.length; k+=9) {
        //     d_sum = d_sum.add(pi3[k]).mod(group.n)
        //     d_prime_sum = d_prime_sum.add(pi3[k + 4]).mod(group.n)
        // }
        // console.log("ZPK3 test 2 candidate " + j + ": " + c.eq(d_sum))
        // //check 3
        // console.log("ZPK3 test 3 candidate " + j + ": " + c.eq(d_prime_sum))
        //
        // //check 4
        // let check4 = true
        // let xi = pi3[0]
        // for (let k = 11; k < pi3.length; k+=9) {
        //     let a = pi3[k]
        //     let d = pi3[k + 2]
        //     let e = pi3[k + 3]
        //     let t = a.eq(group.g.mul(e).add(xi.mul(d)))
        //     check4 = check4 && t
        // }
        // console.log("ZPK3 test 4 candidate " + j + ": " + check4)
        //
        // //check 5
        // let check5 = true
        // let W = getW(votersPublicKeys, myNumber)
        // let nu = pi3[1]
        // for (let k = 12; k < pi3.length; k+=9) {
        //     let b = pi3[k]
        //     let d = pi3[k + 1]
        //     let e = pi3[k + 2]
        //     let pointValue =  Math.floor((k - 11) / 9)
        //     let t = b.eq(W.mul(e).add(nu.add(group.g.mul(pointValue).neg()).mul(d)))
        //     check5 = check5 && t
        // }
        // console.log("ZPK3 test 5 candidate " + j + ": " + check5)
        //
        // //check 6
        // let check6 = true
        // for (let k = 15; k < pi3.length; k+=9) {
        //     let a_prime = pi3[k]
        //     let d_prime = pi3[k + 2]
        //     let e_prime = pi3[k + 3]
        //     let t = a_prime.eq(group.g.mul(e_prime).add(votersPublicKeys[myNumber].mul(d_prime)))
        //     check6 = check6 && t
        // }
        // console.log("ZPK3 test 6 candidate " + j + ": " + check6)
        //
        //check 7
        let check7 = true
        let gamma = B[j].gamma
        for (let k = 8; k < pi3.length; k+=13) {
            let b_prime = group.curve.point(pi3[k + 8], pi3[k + 9])
            let d_prime = pi3[k + 10]
            let e_prime = pi3[k + 11]
            let f_prime = pi3[k + 12]
            let point = (k - 8) / 13 + minScore
            let t = b_prime.eq(W_i.mul(e_prime).add(group.g.mul(f_prime)).add(gamma.add(group.g.mul(point).neg()).mul(d_prime)))
            check7 = check7 && t
        }
        console.log("ZPK3 test 7 candidate " + j + ": " + check7)
    }

    let { Y, Y_new, X_new_new, p_gamma, gamma_new, c} = ZKPoK4(privateKey, votersPublicKeys, p_gamma_, number)
    //check 2
    // console.log("ZPK4 test 1: " + Y_new.eq(Y.mul(c).add(group.g.mul(X_new_new))))
    //
    // //check 3 -- doesn't work for now
    // let r1 = p_gamma.add(group.g.mul(P).add(p_betas).neg()).mul(c)
    // // let r1 = p_betas
    // let r2 = W_i.mul(X_new_new.mul(new BN(candidatesNumber)).mod(group.n))
    // console.log("ZPK4 test 2: " + gamma_new.eq(r1.add(r2)))

    return { B, pi3s }
}

function toPos(n) {
    if (n.isNeg()) {
        n = n.add(group.n)
    }
    return n
}


function main(){
    console.log(group.g.getX().toString())
    console.log(group.g.getY().toString())
    // console.log(group.n.toString())
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
    let randPrivKeys = []
    let randVoteKeys = []
    let randVotePrivateKeys = [] // ONLY FOR TESTING
    for (let i = 0; i < votersNumber; i++) {
        if (i !== myNumber) {
            let k = group.genKeyPair()
            randKeys.push(k.getPublic())
            randPrivKeys.push(k.getPrivate())
        } else {
            randKeys.push(publicKey)
            randPrivKeys.push(privateKey)
        }
        let innerx = []
        let innery = []
        if (i === myNumber) {
            randVotePrivateKeys.push(xs)
            randVoteKeys.push(ys)
        } else {
            for (let j = 1; j <= candidatesNumber; j++) {
                let { x, y } = keyDerive(randPrivKeys[i], j)
                // console.log(y)
                innerx.push(x)
                innery.push(y)
            }
            randVotePrivateKeys.push(innerx)
            randVoteKeys.push(innery)
        }
    }
    let points = [2, 2, 1, 4, 1]

    let { C, pis, ss } = commit(privateKey, points, randKeys, myNumber)
    vote(privateKey, points, randKeys, xs, randVoteKeys, C, ss, myNumber)
    //now we can publish publicKey and ys on blockchain -- call register
}

function selfTally(betas, gammas) {
    let res = []
    let candidatesNumber = betas[0].length / 2;
    let votersNumber = betas.length
    for (let i = 0; i < candidatesNumber; i++) {
        let b_prod = group.g.add(group.g.neg())
        let g_prod = group.g.add(group.g.neg())
        for (let j = 0; j < votersNumber; j++) {
            let new_b = group.curve.point(betas[j][i * 2], betas[j][i * 2 + 1])
            b_prod = b_prod.add(new_b)
            let new_g = group.curve.point(gammas[j][i * 2], gammas[j][i * 2 + 1])
            g_prod = g_prod.add(new_g)
        }
        let r = g_prod.add(b_prod.neg())
        for (let k = 0; k < votersNumber * maxScore; k++) {
            if (r.eq(group.g.mul(k))) {
                res.push(k)
            }
        }
    }
    return res
}

// main()

module.exports = { keyGen, keyDerive, commit, vote, getW, selfTally }