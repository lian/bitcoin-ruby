# encoding: ascii-8bit
# frozen_string_literal: true

require 'spec_helper'

# this spec requires secp256k1 library
describe 'BIP143 spec' do
  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Example
  it 'Native P2WPKH' do
    tx = Bitcoin::Protocol::Tx.new(
      '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad' \
      '969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9' \
      'b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df3' \
      '78db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e' \
      '4dbe6a21b2d50ce2f0167faa815988ac11000000'.htb
    )

    sig_hash0 = tx.signature_hash_for_input(
      0,
      '2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac'.htb
    )
    sig0 = Bitcoin::Secp256k1.sign(
      sig_hash0,
      'bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866'.htb
    ) + [Bitcoin::Protocol::Tx::SIGHASH_TYPE[:all]].pack('C')

    tx.in[0].script_sig = Bitcoin::Script.new(
      Bitcoin::Script.pack_pushdata(sig0)
    ).to_payload

    sig_hash1 = tx.signature_hash_for_witness_input(
      1,
      '00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1'.htb,
      600_000_000
    )
    sig1 = Bitcoin::Secp256k1.sign(
      sig_hash1,
      '619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9'.htb
    ) + [Bitcoin::Protocol::Tx::SIGHASH_TYPE[:all]].pack('C')

    tx.in[1].script_witness.stack << sig1
    tx.in[1].script_witness.stack << '025476c2e83188368da1ff3e292e7acafcdb356' \
                                     '6bb0ad253f62fc70f07aeee6357'.htb

    expect(tx.to_witness_payload.bth)
      .to eq('01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf43' \
             '3541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b0274' \
             '2fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f' \
             '2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804' \
             'cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000000' \
             '0ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a78' \
             '3a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d' \
             '50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5' \
             'b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f9' \
             '0300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368d' \
             'a1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000')
  end

  it 'P2SH-P2WPKH' do
    redeem_script = '001479091972186c449eb1ded22b78e40d009bdf0089'
    tx = Bitcoin::Protocol::Tx.new(
      '0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1' \
      'a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a' \
      '45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea' \
      '7ad0402e8bd8ad6d77c88ac92040000'.htb
    )

    tx.in[0].script_sig = Bitcoin::Script.new(
      Bitcoin::Script.pack_pushdata(redeem_script.htb)
    ).to_payload

    sig_hash = tx.signature_hash_for_witness_input(
      0, redeem_script.htb, 1_000_000_000
    )
    sig = Bitcoin::Secp256k1.sign(
      sig_hash,
      'eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf'.htb
    ) + [Bitcoin::Protocol::Tx::SIGHASH_TYPE[:all]].pack('C')

    tx.in[0].script_witness.stack << sig
    tx.in[0].script_witness.stack << '03ad1d8e89212f0b92c74d23bb710c00662ad1' \
                                     '470198ac48c43f7d6f93a2a26873'.htb

    expect(tx.to_witness_payload.bth)
      .to eq('01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb6609' \
             '2ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d00' \
             '9bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a4' \
             '5bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea' \
             '97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94' \
             'ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c7' \
             '13331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212' \
             'f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000')
  end

  it 'Native P2WSH' do
    # <026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae>
    # CHECKSIGVERIFY CODESEPERATOR
    # <0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465>
    # CHECKSIG this script needs two privkey signature
    witness_script = Bitcoin::Script.new(
      '21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aead' \
      'ab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465' \
      'ac'.htb
    )
    script_pubkey =
      '00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0'

    tx = Bitcoin::Protocol::Tx.new(
      '0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216' \
      'b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47' \
      'c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f814' \
      '5e5acadf23f751864167f32e0963f788ac00000000'.htb
    )

    sig_hash0 = tx.signature_hash_for_input(
      0,
      '21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac'.htb
    )
    sig0 = Bitcoin::Secp256k1.sign(
      sig_hash0,
      'b8f28a772fccbf9b4f58a4f027e07dc2e35e7cd80529975e292ea34f84c4580c'.htb
    ) + [Bitcoin::Protocol::Tx::SIGHASH_TYPE[:all]].pack('C')
    tx.in[0].script_sig = Bitcoin::Script.new(
      Bitcoin::Script.pack_pushdata(sig0)
    ).to_payload

    sig_hash1 = tx.signature_hash_for_witness_input(
      1,
      script_pubkey.htb,
      4_900_000_000,
      witness_script.to_payload,
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:single]
    )
    sig1 = Bitcoin::Secp256k1.sign(
      sig_hash1,
      '8e02b539b1500aa7c81cf3fed177448a546f19d2be416c0c61ff28e577d8d0cd'.htb
    ) + [Bitcoin::Protocol::Tx::SIGHASH_TYPE[:single]].pack('C')

    sig_hash2 = tx.signature_hash_for_witness_input(
      1,
      script_pubkey.htb,
      4_900_000_000,
      witness_script.to_payload,
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:single],
      1
    )
    sig2 = Bitcoin::Secp256k1.sign(
      sig_hash2,
      '86bf2ed75935a0cbef03b89d72034bb4c189d381037a5ac121a70016db8896ec'.htb
    ) + [Bitcoin::Protocol::Tx::SIGHASH_TYPE[:single]].pack('C')

    tx.in[1].script_witness.stack << sig2
    tx.in[1].script_witness.stack << sig1
    tx.in[1].script_witness.stack << witness_script.to_payload

    expect(tx.to_witness_payload.bth)
      .to eq('01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c' \
             '565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73af' \
             '989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295' \
             'b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff0815cf02' \
             '0f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f8000000' \
             '0000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751' \
             '864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e' \
             '214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1' \
             'ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad' \
             '6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a' \
             '9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27' \
             '034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac7' \
             '06453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf08' \
             '6aa8ced5e0d0215ea465ac00000000')
  end

  it 'P2SH-P2WSH' do
    redeem_script =
      '0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54'
    # 6-of-6 multisig
    witness_script = Bitcoin::Script.new(
      '56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3' \
      '2103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21' \
      '034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a2103' \
      '3400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6' \
      'd48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b6' \
      '61b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae'.htb
    )

    tx = Bitcoin::Protocol::Tx.new(
      '010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787' \
      'b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631' \
      'e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84' \
      'c138dbbd3c3ee41588ac00000000'.htb
    )
    tx.in[0].script_sig = Bitcoin::Script.new(
      Bitcoin::Script.pack_pushdata(redeem_script.htb)
    ).to_payload

    tx.in[0].script_witness.stack << ''

    sig_hash0 = tx.signature_hash_for_witness_input(
      0, redeem_script.htb, 987_654_321, witness_script.to_payload
    )
    sig0 = Bitcoin::Secp256k1.sign(
      sig_hash0, '730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6'.htb
    ) + [Bitcoin::Protocol::Tx::SIGHASH_TYPE[:all]].pack('C')
    expect(sig0.bth)
      .to eq('304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6f' \
             'ab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa59481038' \
             '8cf7409a1870ce01')
    tx.in[0].script_witness.stack << sig0

    sig_hash1 = tx.signature_hash_for_witness_input(
      0,
      redeem_script.htb,
      987_654_321,
      witness_script.to_payload,
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:none]
    )
    sig1 = Bitcoin::Secp256k1.sign(
      sig_hash1, '11fa3d25a17cbc22b29c44a484ba552b5a53149d106d3d853e22fdd05a2d8bb3'.htb
    ) + [Bitcoin::Protocol::Tx::SIGHASH_TYPE[:none]].pack('C')
    expect(sig1.bth)
      .to eq('3044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac' \
             '9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc' \
             '6432cdabce271502')
    tx.in[0].script_witness.stack << sig1

    sig_hash2 = tx.signature_hash_for_witness_input(
      0,
      redeem_script.htb,
      987_654_321,
      witness_script.to_payload,
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:single]
    )
    sig2 = Bitcoin::Secp256k1.sign(
      sig_hash2,
      '77bf4141a87d55bdd7f3cd0bdccf6e9e642935fec45f2f30047be7b799120661'.htb
    ) + [Bitcoin::Protocol::Tx::SIGHASH_TYPE[:single]].pack('C')
    expect(sig2.bth)
      .to eq('3044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4f' \
             'a0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fc' \
             'bb15571c76795403')
    tx.in[0].script_witness.stack << sig2

    sig_hash3 = tx.signature_hash_for_witness_input(
      0,
      redeem_script.htb,
      987_654_321,
      witness_script.to_payload,
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:all] | Bitcoin::Protocol::Tx::SIGHASH_TYPE[:anyonecanpay]
    )
    sig3 = Bitcoin::Secp256k1.sign(
      sig_hash3,
      '14af36970f5025ea3e8b5542c0f8ebe7763e674838d08808896b63c3351ffe49'.htb
    ) + [
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:all] |
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:anyonecanpay]
    ].pack('C')
    expect(sig3.bth)
      .to eq('3045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5' \
             'a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b3' \
             '1bb342142a14d16381')
    tx.in[0].script_witness.stack << sig3

    sig_hash4 = tx.signature_hash_for_witness_input(
      0,
      redeem_script.htb,
      987_654_321,
      witness_script.to_payload,
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:none] |
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:anyonecanpay]
    )
    sig4 = Bitcoin::Secp256k1.sign(
      sig_hash4,
      'fe9a95c19eef81dde2b95c1284ef39be497d128e2aa46916fb02d552485e0323'.htb
    ) + [
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:none] |
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:anyonecanpay]
    ].pack('C')
    expect(sig4.bth)
      .to eq('3045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc' \
             '0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501' \
             'd6b3be2e1e1a8a0882')
    tx.in[0].script_witness.stack << sig4

    sig_hash5 = tx.signature_hash_for_witness_input(
      0,
      redeem_script.htb,
      987_654_321,
      witness_script.to_payload,
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:single] |
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:anyonecanpay]
    )
    sig5 = Bitcoin::Secp256k1.sign(
      sig_hash5,
      '428a7aee9f0c2af0cd19af3cf1c78149951ea528726989b2e83e4778d2c3f890'.htb
    ) + [
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:single] |
      Bitcoin::Protocol::Tx::SIGHASH_TYPE[:anyonecanpay]
    ].pack('C')
    expect(sig5.bth)
      .to eq('30440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9f' \
             'e490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9ab' \
             'e12a01a11e2b4783')
    tx.in[0].script_witness.stack << sig5
    tx.in[0].script_witness.stack << witness_script.to_payload

    expect(tx.to_witness_payload.bth)
      .to eq('0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa1' \
             '06c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418' \
             'b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a' \
             '914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f0500000000' \
             '1976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac08004730440' \
             '2206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b7' \
             '3e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf74' \
             '09a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c' \
             '212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64' \
             'eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfe' \
             'c54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2' \
             'b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbef' \
             'd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e022' \
             '03156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d1' \
             '6381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a8' \
             '6de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08' \
             'c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc16' \
             '5497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf' \
             '6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a' \
             '048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28' \
             'bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8' \
             '113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21' \
             '033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a' \
             '8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1' \
             '789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19' \
             '617681024306b56ae00000000')
  end
end
