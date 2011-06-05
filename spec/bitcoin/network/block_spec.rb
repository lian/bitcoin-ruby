
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

  it '#verify_input' do

    block_9 = Bitcoin::Protocol::Block.new(
      # block 9:  000000008d9dc510f23c2657fc4f67bea30078cc05a90eb89e84cc475c080805
      [ "01 00 00 00 c6 0d de f1 b7 61 8c a2 34 8a 46 e8 68 af c2 6e 3e fc 68 22 6c 78 aa 47 f8 48 8c 40 00 00 00 00 c9 97 a5 e5 6e 10 41 02 fa 20 9c 6a 85 2d d9 06 60 a2 0b 2d 9c 35 24 23 ed ce 25 85 7f cd 37 04 7f ca 66 49 ff ff 00 1d 28 40 4f 53 01 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff 07 04 ff ff 00 1d 01 34 ff ff ff ff 01 00 f2 05 2a 01 00 00 00 43 41 04 11 db 93 e1 dc db 8a 01 6b 49 84 0f 8c 53 bc 1e b6 8a 38 2e 97 b1 48 2e ca d7 b1 48 a6 90 9a 5c b2 e0 ea dd fb 84 cc f9 74 44 64 f8 2e 16 0b fa 9b 8b 64 f9 d4 c0 3f 99 9b 86 43 f6 56 b4 12 a3 ac 00 00 00 00"
        .split(" ").join].pack("H*")
    )
    block_9.to_json.should == (<<-TEXT).chomp
{
  "hash": "000000008d9dc510f23c2657fc4f67bea30078cc05a90eb89e84cc475c080805",
  "ver": 1,
  "prev_block": "00000000408c48f847aa786c2268fc3e6ec2af68e8468a34a28c61b7f1de0dc6",
  "mrkl_root": "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9",
  "time": 1231473279,
  "bits": 486604799,
  "nonce": 1397702696,
  "n_tx": 1,
  "size": 215,
  "tx": [
    {
      "hash": "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9",
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
          "coinbase": "04ffff001d0134"
        }
      ],
      "out": [
        {
          "value": "50.00000000",
          "scriptPubKey": "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"
        }
      ]
    }
  ],
  "mrkl_tree": [
    "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9"
  ]
}
    TEXT


    block_170 = Bitcoin::Protocol::Block.new(
      # block 170:  00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee
      [ "01 00 00 00 55 bd 84 0a 78 79 8a d0 da 85 3f 68 97 4f 3d 18 3e 2b d1 db 6a 84 2c 1f ee cf 22 2a 00 00 00 00 ff 10 4c cb 05 42 1a b9 3e 63 f8 c3 ce 5c 2c 2e 9d bb 37 de 27 64 b3 a3 17 5c 81 66 56 2c ac 7d 51 b9 6a 49 ff ff 00 1d 28 3e 9e 70 02 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff 07 04 ff ff 00 1d 01 02 ff ff ff ff 01 00 f2 05 2a 01 00 00 00 43 41 04 d4 6c 49 68 bd e0 28 99 d2 aa 09 63 36 7c 7a 6c e3 4e ec 33 2b 32 e4 2e 5f 34 07 e0 52 d6 4a c6 25 da 6f 07 18 e7 b3 02 14 04 34 bd 72 57 06 95 7c 09 2d b5 38 05 b8 21 a8 5b 23 a7 ac 61 72 5b ac 00 00 00 00 01 00 00 00 01 c9 97 a5 e5 6e 10 41 02 fa 20 9c 6a 85 2d d9 06 60 a2 0b 2d 9c 35 24 23 ed ce 25 85 7f cd 37 04 00 00 00 00 48 47 30 44 02 20 4e 45 e1 69 32 b8 af 51 49 61 a1 d3 a1 a2 5f df 3f 4f 77 32 e9 d6 24 c6 c6 15 48 ab 5f b8 cd 41 02 20 18 15 22 ec 8e ca 07 de 48 60 a4 ac dd 12 90 9d 83 1c c5 6c bb ac 46 22 08 22 21 a8 76 8d 1d 09 01 ff ff ff ff 02 00 ca 9a 3b 00 00 00 00 43 41 04 ae 1a 62 fe 09 c5 f5 1b 13 90 5f 07 f0 6b 99 a2 f7 15 9b 22 25 f3 74 cd 37 8d 71 30 2f a2 84 14 e7 aa b3 73 97 f5 54 a7 df 5f 14 2c 21 c1 b7 30 3b 8a 06 26 f1 ba de d5 c7 2a 70 4f 7e 6c d8 4c ac 00 28 6b ee 00 00 00 00 43 41 04 11 db 93 e1 dc db 8a 01 6b 49 84 0f 8c 53 bc 1e b6 8a 38 2e 97 b1 48 2e ca d7 b1 48 a6 90 9a 5c b2 e0 ea dd fb 84 cc f9 74 44 64 f8 2e 16 0b fa 9b 8b 64 f9 d4 c0 3f 99 9b 86 43 f6 56 b4 12 a3 ac 00 00 00 00"
        .split(" ").join].pack("H*")
    )
    block_170.to_json.should == (<<-TEXT).chomp
{
  "hash": "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee",
  "ver": 1,
  "prev_block": "000000002a22cfee1f2c846adbd12b3e183d4f97683f85dad08a79780a84bd55",
  "mrkl_root": "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff",
  "time": 1231731025,
  "bits": 486604799,
  "nonce": 1889418792,
  "n_tx": 2,
  "size": 490,
  "tx": [
    {
      "hash": "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082",
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
          "coinbase": "04ffff001d0102"
        }
      ],
      "out": [
        {
          "value": "50.00000000",
          "scriptPubKey": "4104d46c4968bde02899d2aa0963367c7a6ce34eec332b32e42e5f3407e052d64ac625da6f0718e7b302140434bd725706957c092db53805b821a85b23a7ac61725bac"
        }
      ]
    },
    {
      "hash": "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
      "ver": 1,
      "vin_sz": 1,
      "vout_sz": 2,
      "lock_time": 0,
      "size": 275,
      "in": [
        {
          "prev_out": {
            "hash": "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9",
            "n": 0
          },
          "scriptSig": "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901 "
        }
      ],
      "out": [
        {
          "value": "10.00000000",
          "scriptPubKey": "4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac"
        },
        {
          "value": "40.00000000",
          "scriptPubKey": "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"
        }
      ]
    }
  ],
  "mrkl_tree": [
    "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082",
    "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
    "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"
  ]
}
    TEXT

    tx = block_170.tx[1]
    signature  = tx.in[0][3][1...-1]
    signature.should ==
      ["304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901"]
        .pack("H*")[0...-1] # last byte is hash_type

    outpoint_tx = block_9.tx[0]
    public_key = outpoint_tx.out[0][2][1...-1].unpack("H*")[0]
    public_key.should ==
      "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"


    hash = tx.signature_hash_for_input(0, outpoint_tx)
    Bitcoin.verify_signature(hash, signature, public_key).should == true

    # yay!
    tx.verify_input_signature(0, outpoint_tx).should == true

  end

end
