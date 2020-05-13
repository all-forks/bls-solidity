import "elliptic-curve-solidity/contracts/EllipticCurve.sol";
pragma solidity >=0.5.3 <0.7.0;


/**
 * @title Elliptic Curve Library
 * @dev Library providing arithmetic operations over elliptic curves.
 * @author Witnet Foundation
 */
library BN256G1 {

  //https://modex.tech/developers/florinotto/go-ethereum/src/a660685746db17a41cd67b05c614cdb29e49340c/core/vm/contracts_test.go

  // Generator coordinate `x` of the EC curve
  uint256 public constant GX = 1;
  // Generator coordinate `y` of the EC curve
  uint256 public constant GY = 2;
  // Constant `a` of EC equation
  uint256 public constant AA = 0;
  // Constant `b` of EC equation
  uint256 public constant BB = 3;
  // Prime number of the curve
  uint256 public constant PP = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
  // Order of the curve
  uint256 public constant NN = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

  /// This is 0xf1f5883e65f820d099915c908786b9d3f58714d70a38f4c22ca2bc723a70f263, the last mulitple of the modulus before 2^256
  uint256 public constant LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256 = 0xf1f5883e65f820d099915c908786b9d3f58714d70a38f4c22ca2bc723a70f263;

  function add(uint256[4] memory input) public returns (uint256[2] memory result) {

    // computes P + Q
    // input: 4 values of 256 bit each
    //  *) x-coordinate of point P
    //  *) y-coordinate of point P
    //  *) x-coordinate of point Q
    //  *) y-coordinate of point Q

    bool success;
    assembly {
    // 0x06     id of precompiled bn256Add contract
    // 0        number of ether to transfer
    // 128      size of call parameters, i.e. 128 bytes total
    // 64       size of call return value, i.e. 64 bytes / 512 bit for a BN256 curve point
      success := call(not(0), 0x06, 0, input, 128, result, 64)
    }
    require(success, "bn256 addition failed");

    return result;
  }

  function multiply(uint256[3] memory input) public returns (uint256[2] memory result) {
    // computes P*x
    // input: 3 values of 256 bit each
    //  *) x-coordinate of point P
    //  *) y-coordinate of point P
    //  *) scalar x

    bool success;
    assembly {
      // 0x07     id of precompiled bn256ScalarMul contract
      // 0        number of ether to transfer
      // 96       size of call parameters, i.e. 96 bytes total (256 bit for x, 256 bit for y, 256 bit for scalar)
      // 64       size of call return value, i.e. 64 bytes / 512 bit for a BN256 curve point
      success := call(not(0), 0x07, 0, input, 96, result, 64)
    }
    require(success, "elliptic curve multiplication failed");
  }

  function isOnCurveSubsidized(uint[2] memory point) public returns(bool valid) {
    // checks if the given point is a valid point from the first elliptic curve group
    // by trying an addition with the generator point g1
    uint256[4] memory input = [
      point[0],
      point[1],
      GX,
      GY];

    assembly {
      // 0x06     id of precompiled bn256Add contract
      // 0        number of ether to transfer
      // 128      size of call parameters, i.e. 128 bytes total
      // 64       size of call return value, i.e. 64 bytes / 512 bit for a BN256 curve point
      valid := call(not(0), 0x06, 0, input, 128, input, 64)
    }
  }

  function isOnCurve(uint[2] memory point) public returns(bool valid) {

    return EllipticCurve.isOnCurve(
      point[0],
      point[1],
      AA,
      BB,
      PP);
  }

  function bn256CheckPairing(uint256[12] memory input) public returns (bool) {
    uint256[1] memory result;
    bool success;
    assembly {
      // 0x08     id of precompiled bn256Pairing contract     (checking the elliptic curve pairings)
      // 0        number of ether to transfer
      // 0        since we have an array of fixed length, our input starts in 0
      // 384      size of call parameters, i.e. 12*256 bits == 384 bytes
      // 32       size of result (one 32 byte boolean!)
      success := call(sub(gas(), 2000), 0x08, 0, input, 384, result, 32)
    }
    require(success, "elliptic curve pairing failed");
    return result[0] == 1;
  }

  // The first point in G1 should be equal to the sum of the following points in G1 inserted
  // Remember the first point in G1 should be negated! -P = (x, q-y)
  function bn256CheckPairingBatch(uint256[] memory input) public returns (bool) {
    uint256[1] memory result;
    bool success;
    require(input.length % 6 == 0, "Incorrect input length");
    uint256 inLen = input.length * 32;
    //uint256 inputBytes = input.length*32;
    assembly {
      // 0x08     id of precompiled bn256Pairing contract     (checking the elliptic curve pairings)
      // 0        number of ether to transfer
      // add(input, 0x20) since we have an unbounded array, the first 256 bits refer to its length
      // 384      size of call parameters, i.e. 12*256 bits == 384 bytes
      // 32       size of result (one 32 byte boolean!)
      success := call(sub(gas(), 2000), 0x08, 0, add(input, 0x20), inLen, result, 32)
    }
    require(success, "elliptic curve pairing failed");
    return result[0] == 1;
  }

  // @dev Function to convert a `Hash(msg|DATA)` to a point in the curve as defined in [VRF-draft-04](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04).
  /// @param _message The message used for computing the VRF
  /// @return The hash point in affine cooridnates
  function hashToTryAndIncrement(bytes memory _message) internal returns (uint, uint) {
    // find a valid EC point
    // Loop over counter ctr starting at 0x00 and do hash
    for (uint8 ctr = 0; ctr < 256; ctr++) {
      // Counter update
      // c[cLength-1] = byte(ctr);
      bytes32 sha = sha256(abi.encodePacked(_message, ctr));
      // Step 4: arbitraty string to point and check if it is on curve
      uint hPointX = uint256(sha);
      if (hPointX >= LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256) continue;
      // Do the modulus to avoid excesive iterations of the loop
      hPointX = hPointX % PP;
      uint hPointY = deriveY(2, hPointX);
      // we do not use the subsidized one as it appears to consume more gas
      if (isOnCurve([
        hPointX,
        hPointY]
      ))
      {
        // Step 5 (omitted): calculate H (cofactor is 1 on bn256g1)
        // If H is not "INVALID" and cofactor > 1, set H = cofactor * H
        return (hPointX, hPointY);
      }
    }
    revert("No valid point was found");
  }

  /// @dev Function to derive the `y` coordinate given the `x` coordinate and the parity byte (`0x03` for odd `y` and `0x04` for even `y`).
  /// @param _yByte The parity byte following the ec point compressed format
  /// @param _x The coordinate `x` of the point
  /// @return The coordinate `y` of the point
  function deriveY(uint8 _yByte, uint256 _x) internal pure returns (uint256) {
    return EllipticCurve.deriveY(
      _yByte,
      _x,
      AA,
      BB,
      PP);
  }

}