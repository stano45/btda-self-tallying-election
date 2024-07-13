// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// contract for operations on secp256k1 curve
contract Crypto {
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
}
