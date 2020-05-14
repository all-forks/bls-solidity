const BN256G1 = artifacts.require("BN256G1")
const BN256G1Helper = artifacts.require("BN256G1Helper")


contract("EcGasHelper - Gas consumption analysis", accounts => {
  // /////////////////////////////////////////// //
  // Check auxiliary operations for given curves //
  // /////////////////////////////////////////// //
  describe(`BN256G1 operations`, () => {
    const curveData = require(`./data/bn256_g1.json`)

    let library
    let bn256g1helper
      before(async () => {
        library = await BN256G1.deployed()
        await BN256G1Helper.link(BN256G1, library.address)
        bn256g1helper = await BN256G1Helper.new()
    })

    // Add
    for (const [index, test] of curveData.addition.valid.entries()) {
      it(`should add two points (${index + 1})`, async () => {
        let add = await bn256g1helper._add.call([
          web3.utils.toBN(test.input.x1),
          web3.utils.toBN(test.input.y1),
          web3.utils.toBN(test.input.x2),
          web3.utils.toBN(test.input.y2)])
	    assert.equal(add[0].toString(), web3.utils.toBN(test.output.x).toString())
	    assert.equal(add[1].toString(), web3.utils.toBN(test.output.y).toString())
      })
    }
    
    // Mul
    for (const [index, test] of curveData.multiplication.valid.entries()) {
      it(`should mul a point with a scalar (${index + 1})`, async () => {
        let mul = await bn256g1helper._multiply.call([
          web3.utils.toBN(test.input.x),
          web3.utils.toBN(test.input.y),
          web3.utils.toBN(test.input.k)])
	    assert.equal(mul[0].toString(), web3.utils.toBN(test.output.x).toString())
	    assert.equal(mul[1].toString(), web3.utils.toBN(test.output.y).toString())
      })
    }
    // Pair
    for (const [index, test] of curveData.pairing.valid.entries()) {
      it(`should check pair (${index + 1})`, async () => {
        let pair = await bn256g1helper._bn256CheckPairing.call([
          web3.utils.toBN(test.input.x1_g1),
          web3.utils.toBN(test.input.y1_g1),
          web3.utils.toBN(test.input.x1_re_g2),
          web3.utils.toBN(test.input.x1_im_g2),
          web3.utils.toBN(test.input.y1_re_g2),
          web3.utils.toBN(test.input.y1_im_g2),
          web3.utils.toBN(test.input.x2_g1),
          web3.utils.toBN(test.input.y2_g1),
          web3.utils.toBN(test.input.x2_re_g2),
          web3.utils.toBN(test.input.x2_im_g2),
          web3.utils.toBN(test.input.y2_re_g2),
          web3.utils.toBN(test.input.y2_im_g2)])
	      assert.equal(pair, test.output.success)
      })
    }

    // Batch Pair
    for (const [index, test] of curveData.pairing_batch.valid.entries()) {
      it(`should check batch pair (${index + 1})`, async () => {
        let pair = await bn256g1helper._bn256CheckPairingBatch.call([
          web3.utils.toBN(test.input.x1_g1),
          web3.utils.toBN(test.input.y1_g1),
          web3.utils.toBN(test.input.x1_re_g2),
          web3.utils.toBN(test.input.x1_im_g2),
          web3.utils.toBN(test.input.y1_re_g2),
          web3.utils.toBN(test.input.y1_im_g2),
          web3.utils.toBN(test.input.x2_g1),
          web3.utils.toBN(test.input.y2_g1),
          web3.utils.toBN(test.input.x2_re_g2),
          web3.utils.toBN(test.input.x2_im_g2),
          web3.utils.toBN(test.input.y2_re_g2),
          web3.utils.toBN(test.input.y2_im_g2),
          web3.utils.toBN(test.input.x3_g1),
          web3.utils.toBN(test.input.y3_g1),
          web3.utils.toBN(test.input.x3_re_g2),
          web3.utils.toBN(test.input.x3_im_g2),
          web3.utils.toBN(test.input.y3_re_g2),
        web3.utils.toBN(test.input.y3_im_g2)
      ])
	      assert.equal(pair, test.output.success)
      })
    }
    
    // Hash to curve
    for (const [index, test] of curveData.hash_to_try.valid.entries()) {
      it(`should check hash_to_try (${index + 1})`, async () => {
        let hash = await bn256g1helper._hashToTryAndIncrement.call(
          test.input.message
      )
	    assert.equal(hash[0].toString(), web3.utils.toBN(test.output.hash).toString())
      })
    }
  })
})
