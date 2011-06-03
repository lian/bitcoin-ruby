
require_relative '../spec_helper.rb'

require 'bitcoin/network'

describe 'Bitcoin::Protocol::Tx' do

  it '#new' do
    proc{
      Bitcoin::Protocol::Block.new( nil )

      @block = Bitcoin::Protocol::Block.new(
        # block 1:  00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
        [ "01 00 00 00 6f e2 8c 0a b6 f1 b3 72 c1 a6 a2 46 ae 63 f7 4f 93 1e 83 65 e1 5a 08 9c 68 d6 19 00 00 00 00 00 98 20 51 fd 1e 4b a7 44 bb be 68 0e 1f ee 14 67 7b a1 a3 c3 54 0b f7 b1 cd b6 06 e8 57 23 3e 0e 61 bc 66 49 ff ff 00 1d 01 e3 62 99 01 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff 07 04 ff ff 00 1d 01 04 ff ff ff ff 01 00 f2 05 2a 01 00 00 00 43 41 04 96 b5 38 e8 53 51 9c 72 6a 2c 91 e6 1e c1 16 00 ae 13 90 81 3a 62 7c 66 fb 8b e7 94 7b e6 3c 52 da 75 89 37 95 15 d4 e0 a6 04 f8 14 17 81 e6 22 94 72 11 66 bf 62 1e 73 a8 2c bf 23 42 c8 58 ee ac 00 00 00 00"
          .split(" ").join].pack("H*")
      )

    }.should.not.raise Exception

    proc{
      Bitcoin::Protocol::Tx.new( @payload[0][0..20] )
    }.should.raise Exception
  end

  it '#hash' do
    @block.hash.should == "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
  end

  it '#tx' do
    @block.tx.size.should == 1
    @block.tx[0].is_a?(Bitcoin::Protocol::Tx).should == true
    @block.tx[0].hash.should == "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
  end

  it '#to_hash' do
    @block.to_hash.keys.should == ["hash", "ver", "prev_block", "mrkl_root", "time", "bits", "nonce", "n_tx", "size", "tx", "mrkl_tree"]
  end

  it '#to_json' do
    @block.to_json.should == (<<-TEXT).chomp
{
  "hash": "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
  "ver": 1,
  "prev_block": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
  "mrkl_root": "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
  "time": 1231469665,
  "bits": 486604799,
  "nonce": 2573394689,
  "n_tx": 1,
  "size": 215,
  "tx": [
    {
      "hash": "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
      "ver": 1,
      "vin_sz": 1,
      "vout_sz": 1,
      "lock_time": 0,
      "size": 134,
      "in": [
        {
          "prev_out": {
            "hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "n": 4294967295
          },
          "coinbase": "04ffff001d0104"
        }
      ],
      "out": [
        {
          "value": "50.00000000",
          "scriptPubKey": "410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac"
        }
      ]
    }
  ],
  "mrkl_tree": [
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
  ]
}
    TEXT



    Bitcoin::Protocol::Block.new(

      # block 2:  000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd
      [ "01 00 00 00 48 60 eb 18 bf 1b 16 20 e3 7e 94 90 fc 8a 42 75 14 41 6f d7 51 59 ab 86 68 8e 9a 83 00 00 00 00 d5 fd cc 54 1e 25 de 1c 7a 5a dd ed f2 48 58 b8 bb 66 5c 9f 36 ef 74 4e e4 2c 31 60 22 c9 0f 9b b0 bc 66 49 ff ff 00 1d 08 d2 bd 61 01 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff 07 04 ff ff 00 1d 01 0b ff ff ff ff 01 00 f2 05 2a 01 00 00 00 43 41 04 72 11 a8 24 f5 5b 50 52 28 e4 c3 d5 19 4c 1f cf aa 15 a4 56 ab df 37 f9 b9 d9 7a 40 40 af c0 73 de e6 c8 90 64 98 4f 03 38 52 37 d9 21 67 c1 3e 23 64 46 b4 17 ab 79 a0 fc ae 41 2a e3 31 6b 77 ac 00 00 00 00"
        .split(" ").join].pack("H*")

    ).to_json.should == (<<-TEXT).chomp
{
  "hash": "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd",
  "ver": 1,
  "prev_block": "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
  "mrkl_root": "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5",
  "time": 1231469744,
  "bits": 486604799,
  "nonce": 1639830024,
  "n_tx": 1,
  "size": 215,
  "tx": [
    {
      "hash": "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5",
      "ver": 1,
      "vin_sz": 1,
      "vout_sz": 1,
      "lock_time": 0,
      "size": 134,
      "in": [
        {
          "prev_out": {
            "hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "n": 4294967295
          },
          "coinbase": "04ffff001d010b"
        }
      ],
      "out": [
        {
          "value": "50.00000000",
          "scriptPubKey": "41047211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073dee6c89064984f03385237d92167c13e236446b417ab79a0fcae412ae3316b77ac"
        }
      ]
    }
  ],
  "mrkl_tree": [
    "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5"
  ]
}
    TEXT
  end

end
