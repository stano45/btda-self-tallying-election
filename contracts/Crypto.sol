// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// contract for operations on secp256k1 curve
contract Crypto {
    uint256 constant public gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240;
    uint256 constant public gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424;
    uint256 constant public q =  115792089237316195423570985008687907852837564279074904382605163141518161494337; // curve order
    uint256 constant public p =  115792089237316195423570985008687907853269984665640564039457584007908834671663; // curve modulus

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
