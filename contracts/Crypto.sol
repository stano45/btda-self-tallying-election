// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import "./ScoreVoting.sol";

contract Crypto {
    struct ZKPoK3_data {
        uint[2] a;
        uint[2] b;
        uint d;
        uint e;
        uint[2] a_prime;
        uint[2] b_prime;
        uint d_prime;
        uint e_prime;
        uint f_prime;
        uint[2] Z;
        uint i;
    }

    struct ZKPoK4_proof {
        uint[2] Y_new;
        uint X_new_new;
        uint[2] gamma_new;
        uint c;
    }

    uint256 constant public gx = 19823850254741169819033785099293761935467223354323761392354670518001715552183;
    uint256 constant public gy = 15097907474011103550430959168661954736283086276546887690628027914974507414020;
    uint256 constant public q =  21888242871839275222246405745257275088548364400416034343698204186575808495617; // curve order
    uint256 constant public p =  21888242871839275222246405745257275088696311157297823662689037894645226208583; // curve modulus

    function ecAdd(uint[2] memory p1, uint[2] memory p2) public view returns (uint[2] memory r) {
        uint256[4] memory input = [p1[0],p1[1],p2[0],p2[1]];
        assembly {
            if iszero(staticcall(not(0), 6, input, 0x80, r, 0x40)) {
                revert(0, 0)
            }
        }
    }

    function ecMul(uint s, uint[2] memory p1) public view returns (uint[2] memory r) {
        uint256[3] memory input = [p1[0],p1[1],s];
        assembly {
            if iszero(staticcall(not(0), 7, input, 0x60, r, 0x40)) {
                revert(0, 0)
            }
        }
    }

    function ecMul(uint s) public view returns (uint[2] memory r) {
        r = ecMul(s,[gx,gy]);
    }

    function ecNeg(uint[2] memory p1) public pure returns (uint[2] memory) {
        if (p1[0] == 0 && p1[1] == 0)
            return p1;
        p1[1] = p - p1[1];
        return p1;
    }

    function Add(uint x, uint y) public pure returns (uint) {
        return addmod(x, y, q);
    }

    function Mul(uint x, uint y) public pure returns (uint) {
        return mulmod(x, y, q);
    }

    function Sub(uint256 x, uint256 y) public pure returns (uint256) {
        return x >= y ? x - y : q - y + x;
    }

    function Equal(uint[2] memory x, uint[2] memory y) public pure returns (bool) {
        return x[0] == y[0] && x[1] == y[1];
    }

    function Mod(uint256 x) public pure returns (uint256) {
       return x % q;
    }

    function checkZKPoK1(ScoreVoting.ZKPoK1_Proof_API memory pr) public view returns (bool) {
        ScoreVoting.ZKPoK1_Proof memory pp;
        bool result = true;
        for (uint i = 0; i < pr.candidateCount; i++) {
            uint d_sum = 0;
            pp.xi = [pr.xis[i * 2], pr.xis[i * 2 + 1]];
            pp.nu = [pr.nus[i * 2], pr.nus[i * 2 + 1]];
            pp.c = pr.proof[i][0];
            pp.X = pr.proof[i][1];
            pp.Y = [pr.proof[i][2], pr.proof[i][3]];
            for (uint j = pr.minScore; j <= pr.maxScore; j++) {
                d_sum = Add(d_sum, pr.proof[i][8 + (j - pr.minScore) * 6]);
                result = result && ZKPoK1_Inners(pp.xi, pp.nu, pr.proof[i], j, pr.W_i, pr.minScore);
            }
            result = result && (pp.c == d_sum); // c = sum d
            result = result && (Equal(
                pp.Y,
                ecAdd(
                    ecMul(pp.c, pr.publicKey),
                    ecMul(pp.X)
                )
            )); // Y = pubKey^c * g^X
        }
        return result;
    }

    function ZKPoK1_Inners(uint[2] memory xi, uint[2] memory nu, uint[] memory proof, uint j, uint[2] memory W_i, uint minScore) private view returns (bool) {
        bool result = true;
        ScoreVoting.Point memory a;
        a.data = [proof[4 + (j - minScore) * 6], proof[5 + (j - minScore) * 6]];
        ScoreVoting.Point memory b;
        b.data = [proof[6 + (j - minScore) * 6], proof[7 + (j - minScore) * 6]];
        uint d = proof[8 + (j - minScore) * 6];
        uint e = proof[9 + (j - minScore) * 6];
        result = result && ZKPoK11(xi, a.data, d, e); // a == g^e xi^d
        result = result && ZKPoK12(nu, W_i, b.data, d, e, j); // check that b equals W_i^e * (nu/g^j)^d
        return result;
    }


    function ZKPoK11(uint[2] memory xi, uint[2] memory a, uint d, uint e) public view returns (bool) {
        return Equal(
            ecAdd(ecMul(e), ecMul(d, xi)),
            a
        );
    }

    function ZKPoK12(uint[2] memory nu, uint[2] memory W_i, uint[2] memory b, uint d, uint e, uint j) public view returns (bool) {
        uint[2] memory div = ecAdd(nu, ecNeg(ecMul(j)));
        return Equal(
            ecAdd(
                ecMul(e, W_i),
                ecMul(d, div)),
            b
        );
    }

    function checkZKPoK2(uint[] memory proof, uint[2] memory W_i, uint totalScore) public view returns (bool) {
        ScoreVoting.ZKPoK2_Proof memory pp;
        pp.xi = [proof[0], proof[1]];
        pp.xi_new = [proof[2], proof[3]];
        pp.nu = [proof[4], proof[5]];
        pp.nu_new = [proof[6], proof[7]];
        pp.s_s_new = proof[8];
        pp.c = proof[9];
        bool result = true;
        uint c = uint(keccak256(abi.encodePacked([
            proof[0], proof[1], proof[2], proof[3],
            proof[4], proof[5], proof[6], proof[7]
        ])));
        result = result && c == pp.c; // hashed values equal

        result = result && Equal(
            pp.xi_new,
            ecAdd(
                ecMul(c, pp.xi),
                ecMul(proof[8])
            )
        ); // p_xi_new == (p_xi)^c * g^s_s_new

        result = result && Equal(
            pp.nu_new,
            ecAdd(
                ecMul(c,
                    ecAdd(
                        pp.nu,
                        ecNeg(ecMul(totalScore))
                    )
                ),
                ecMul(pp.s_s_new, W_i)
            )
        );

        return result;
    }


    function checkZKPoK3_1(ScoreVoting.ZKPoK3_Proof_API memory pr) public view returns (bool) {
        ScoreVoting.ZKPoK3_Proof memory pp;
        bool result = true;
        uint[] memory toHash = new uint[](14 + 8 * (pr.maxScore - pr.minScore + 1));
        uint d_sum = 0;
        uint d_prime_sum = 0;

        for (uint i = 0; i < pr.candidateCount; i++) {
            pp.xi = [pr.xis[i * 2], pr.xis[i * 2 + 1]];
            pp.nu = [pr.nus[i * 2], pr.nus[i * 2 + 1]];
            pp.beta = [pr.betas[i * 2], pr.betas[i * 2 + 1]];
            pp.gamma = [pr.gammas[i * 2], pr.gammas[i * 2 + 1]];
            pp.y = [pr.publicKeysForCandidates[i * 2], pr.publicKeysForCandidates[i * 2 + 1]];
            pp.y_new = [pr.proof[i][1], pr.proof[i][2]];
            pp.beta_new = [pr.proof[i][3], pr.proof[i][4]];
            pp.c = pr.proof[i][0];
            pp.X_new = pr.proof[i][5];
            pp.x_new = pr.proof[i][6];
            pp.r_new = pr.proof[i][7];
            toHash[0] = pp.xi[0];
            toHash[1] = pp.xi[1];
            toHash[2] = pp.nu[0];
            toHash[3] = pp.nu[1];
            toHash[4] = pp.gamma[0];
            toHash[5] = pp.gamma[1];
            toHash[6] = pp.y[0];
            toHash[7] = pp.y[1];
            toHash[8] = pp.y_new[0];
            toHash[9] = pp.y_new[1];
            toHash[10] = pp.beta[0];
            toHash[11] = pp.beta[1];
            toHash[12] = pp.beta_new[0];
            toHash[13] = pp.beta_new[1];
            d_sum = 0;
            d_prime_sum = 0;
            for (uint j = 8; j < pr.proof[i].length; j += 13) {
                d_sum = Add(d_sum, pr.proof[i][j + 4]);
                d_prime_sum = Add(d_prime_sum, pr.proof[i][j + 10]);
                uint k = (j - 8) / 13;

                toHash[14 + k * 8] = pr.proof[i][j];
                toHash[15 + k * 8] = pr.proof[i][j + 1];
                toHash[16 + k * 8] = pr.proof[i][j + 2];
                toHash[17 + k * 8] = pr.proof[i][j + 3];
                toHash[18 + k * 8] = pr.proof[i][j + 6];
                toHash[19 + k * 8] = pr.proof[i][j + 7];
                toHash[20 + k * 8] = pr.proof[i][j + 8];
                toHash[21 + k * 8] = pr.proof[i][j + 9];
            }
            uint c = Mod(uint(keccak256(abi.encodePacked(toHash))));
            result = result && c == pp.c;
            result = result && d_sum == pp.c; // c == d_sum
            result = result && d_prime_sum == pp.c; // c == d_prime_sum
        }

        return result;
    }

    function checkZKPoK3_2(ScoreVoting.ZKPoK3_Proof_API memory pr) public view returns (bool) {
        ScoreVoting.ZKPoK3_Proof memory pp;
        bool result = true;
        ZKPoK3_data memory d;
        for (uint i = 0; i < pr.candidateCount; i++) {
            uint j = 0;
            pp.xi = [pr.xis[i * 2], pr.xis[i * 2 + 1]];
            pp.nu = [pr.nus[i * 2], pr.nus[i * 2 + 1]];
            pp.beta = [pr.betas[i * 2], pr.betas[i * 2 + 1]];
            pp.gamma = [pr.gammas[i * 2], pr.gammas[i * 2 + 1]];
            pp.c = pr.proof[i][0];
            pp.y_new = [pr.proof[i][1], pr.proof[i][2]];
            pp.beta_new = [pr.proof[i][3], pr.proof[i][4]];
            pp.X_new = pr.proof[i][5];
            pp.x_new = pr.proof[i][6];
            pp.r_new = pr.proof[i][7];

            for (uint j = 8; j < pr.proof[i].length; j += 13) {

                d.a = [pr.proof[i][j], pr.proof[i][j + 1]];
                d.b = [pr.proof[i][j + 2], pr.proof[i][j + 3]];
                d.d = pr.proof[i][j + 4];
                d.e = pr.proof[i][j + 5];
                d.a_prime = [pr.proof[i][j + 6], pr.proof[i][j + 7]];
                d.b_prime = [pr.proof[i][j + 8], pr.proof[i][j + 9]];
                d.d_prime = pr.proof[i][j + 10];
                d.e_prime = pr.proof[i][j + 11];
                d.f_prime = pr.proof[i][j + 12];

                d.i = (j - 8) / 13 + pr.minScore;
                d.Z = [pr.Zs[i * 2], pr.Zs[i * 2 + 1]];

                result = result && ZKPoK3_Point_1(pp.xi, pp.nu, d, pr.W_i, d.i);

                result = result && ZKPoK3_Point_2(d.a_prime, d.d_prime, d.e_prime, pr.publicKey);

                result = result && ZKPoK3_Point_3(pp.gamma, d, pr.W_i, d.i);

                result = result && Equal(
                    pp.beta_new,
                    ecAdd(
                        ecMul(pp.c, pp.beta),
                        ecAdd(
                            ecMul(pp.x_new, d.Z),
                            ecMul(pp.r_new)
                        )
                    )
                );
            }
        }


        return result;
    }

    function ZKPoK3_Point_1(
        uint[2] memory xi, uint[2] memory nu, ZKPoK3_data memory pp, uint[2] memory W_i, uint i) public view returns (bool) {
        bool result = true;
        result = result && Equal(
            pp.a,
            ecAdd(
                ecMul(pp.e),
                ecMul(pp.d, xi)
            )
        ); // a = g^e * xi^d
        result = result && Equal(
            pp.b,
            ecAdd(
                ecMul(pp.e, W_i),
                ecMul(
                    pp.d,
                    ecAdd(nu, ecNeg(ecMul(i)))
                )
            )
        ); // b = W_i^e * (nu/g^i)^d
        return result;
    }

    function ZKPoK3_Point_2(uint[2] memory a_prime, uint d_prime, uint e_prime, uint[2] memory publicKey) public view returns (bool) {
        return Equal(
            a_prime,
            ecAdd(
                ecMul(e_prime),
                ecMul(d_prime, publicKey)
            )
        );
    }

    function ZKPoK3_Point_3(uint[2] memory gamma, ZKPoK3_data memory pp, uint[2] memory W_i, uint i) public view returns (bool) {
        return Equal(
            pp.b_prime,
            ecAdd(
                ecAdd(
                    ecMul(pp.e_prime, W_i),
                    ecMul(pp.f_prime)
                ),
                ecMul(
                    pp.d_prime,
                    ecAdd(
                        gamma,
                        ecNeg(ecMul(i))
                    )
                )
            )
        );
    }

    function checkZKPoK4(uint[] memory proof, uint[] memory gammas, uint[2] memory publicKey, uint candidateCount) public view returns (bool) {
        bool result = true;
        uint[2] memory p_gamma = ecMul(0);
        ZKPoK4_proof memory pp;
        pp.Y_new = [proof[0], proof[1]];
        pp.X_new_new = proof[2];
        pp.gamma_new = [proof[3], proof[4]];
        pp.c = proof[5];
        for (uint i = 0; i < candidateCount; i++) {
            p_gamma = ecAdd([gammas[i * 2], gammas[i * 2 + 1]], p_gamma);
        }
        uint c = Mod(uint(keccak256(abi.encodePacked(
            [publicKey[0], publicKey[1], pp.Y_new[0], pp.Y_new[1], p_gamma[0], p_gamma[1], pp.gamma_new[0], pp.gamma_new[1]]
        ))));
        result = result && pp.c == c;
        result = result && Equal(
            pp.Y_new,
            ecAdd(
                ecMul(pp.c, publicKey),
                ecMul(pp.X_new_new)
            )
        );
        return result;
    }
}
