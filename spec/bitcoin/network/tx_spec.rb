require_relative '../spec_helper.rb'

require 'bitcoin/network'

describe 'Bitcoin::Protocol::Tx' do

  @payload = [
    [ "f9 be b4 d9 74 78 00 00 00 00 00 00 00 00 00 00 02 01 00 00 b4 02 2d 9f 01 00 00 00 01 b0 f6 36 83 43 fc 1e d0 63 57 08 0f 2d 76 51 a7 7b 48 66 6a f2 86 28 63 ce 36 0e ea 2a fc 66 c8 00 00 00 00 8b 48 30 45 02 21 00 bd e2 e7 02 38 08 13 d6 10 69 84 5a 75 e3 30 77 9b ba cc 6a 13 30 bd 9d fd 1f ec 1b d9 4f 8f 17 02 20 75 c2 9d 9b 37 95 7c 80 06 84 36 60 97 55 94 2b e0 f7 f6 fb d3 09 83 a5 57 a6 e0 64 0e de eb 16 01 41 04 9d e8 9d d4 f0 b3 80 1c 2d 28 a3 34 f0 fb 8b 0b fd 7a 9d 67 53 0e 9d ff a5 36 bd 71 30 e8 df d3 2a 01 e7 ba fc dd 95 6f de ec e0 f3 41 fa 4f 27 27 89 0b f0 9f e0 dd 1d ea 91 69 aa d9 c3 02 42 ff ff ff ff 02 dd cd 7c 01 00 00 00 00 19 76 a9 14 b2 e2 1c 1d b9 22 e3 bd c5 29 de 7b 38 b4 c4 01 39 9e 9a fd 88 ac 13 f0 3c 00 00 00 00 00 19 76 a9 14 77 66 34 7a 89 06 38 dc 3c d8 d4 ef 99 b8 e4 0c 65 19 d1 1e 88 ac 00 00 00 00"
      .split(" ").join].pack("H*")[24..-1],
    [ "f9 be b4 d9 74 78 00 00 00 00 00 00 00 00 00 00 02 01 00 00 a5 32 41 1a 01 00 00 00 01 e1 3e 95 12 28 38 40 14 cd e9 9e 7d 9d 02 e9 d5 ed d5 28 23 59 bc 7a ec 12 1b e0 a6 b3 13 be 0a 00 00 00 00 8b 48 30 45 02 20 74 42 f4 2b b0 c6 4f 94 8d f0 71 1a e6 1e 86 12 a0 11 d8 3e 75 55 07 d7 3c 8c f6 b1 ae 71 fc d5 02 21 00 a6 1a 91 f4 26 a2 0d b8 77 8e 35 d1 47 92 f6 4d aa 0e 8e df 2a cd 5a 93 29 ad c2 5e 00 74 a2 cf 01 41 04 58 33 aa 16 77 dc 0f 5b d7 73 b8 35 62 2d 53 b4 d3 1b c1 94 57 72 90 a4 88 97 fb 15 7e 6a f9 25 be c9 ce 0d ad 4f c9 e6 13 d9 d4 66 1d 78 c1 11 b0 2f 21 9c a4 46 e0 c1 01 b7 30 d1 23 4c 49 78 ff ff ff ff 02 40 95 ce f9 02 00 00 00 19 76 a9 14 7b c2 e1 9b 0a fd 1c 78 ec 79 2b ba d3 34 d4 1d b2 da 88 45 88 ac 40 8a f7 01 00 00 00 00 19 76 a9 14 ff ad 3e 6d dc fd b4 12 95 3d 41 88 7a 21 e9 ff 98 05 a9 3c 88 ac 00 00 00 00"
      .split(" ").join].pack("H*")[24..-1],
    [ "f9 be b4 d9 74 78 00 00 00 00 00 00 00 00 00 00 1e 03 00 00 bc 59 11 10 01 00 00 00 04 65 f8 ac 87 e6 29 78 10 79 f8 bf 5b 4d a3 f8 ca 9d 39 f4 5e 86 51 b0 4e 7f 65 eb a1 99 06 13 1f 00 00 00 00 8b 48 30 45 02 21 00 fd 9d 06 ec 1b 74 06 0a 6e 85 e2 ff 61 4d 4c f0 1c 41 a3 0d eb d8 6a c6 69 ee 53 70 b0 38 a2 93 02 20 4c e4 59 5e a7 65 8b a2 a1 48 7a a7 84 ed 75 43 d0 b3 94 b0 39 3d 73 2a 3e a4 f2 47 ff d7 f4 93 01 41 04 97 4d ed df 7b 6d bf db e6 79 9f 58 b4 46 0b 0f 80 e6 09 d5 2d 5a b1 3c 39 8b 84 56 c8 dd 9e a2 9f c6 70 2a 69 ed fe 76 bd 2b 7e 73 61 e0 a8 15 23 cb a3 42 13 3e d0 e2 70 b2 d3 8e 51 42 9a 33 ff ff ff ff 84 6f 55 13 94 6e dc e6 f8 0b 2a dc d8 34 ef 3e c7 24 31 aa ea fc c0 d1 7d 3b 2e 75 a4 5b fe d9 00 00 00 00 8b 48 30 45 02 21 00 96 78 2e 8d 62 ec 98 f1 4b 51 63 9a 0a a0 45 88 f8 47 ea 12 4d 97 09 d2 e4 8e c6 49 d5 62 ed 06 02 20 3d 5a 6f ec 66 af 25 18 96 0b db af 55 6d 10 73 28 82 ad 95 63 d8 ec 38 c2 2a 16 68 30 6a 5a cf 01 41 04 b6 5a 4e 77 5c 8d 55 67 6d dd 25 f9 72 36 c6 b4 52 b5 ab 98 6e 2e d7 56 2d b4 53 eb ce 7c 95 ba df b8 90 e0 da 26 53 74 7a 21 b4 63 c6 3e b8 ba 6a b9 ff 9c e2 68 a3 60 0c 1b 90 6d 5e 29 56 95 ff ff ff ff cf ef e1 a4 c4 2f ca b5 14 cc 2d 96 8c 8d c1 17 7d 3d c3 68 11 b1 e6 77 70 40 0f 7f d7 f4 34 d6 00 00 00 00 8a 47 30 44 02 20 25 c8 99 f5 0e 42 b7 9a 25 8d 10 a9 41 e6 15 29 d4 ad 1e 1d 5d fd 89 1e e2 43 a1 86 fb bb f8 1f 02 20 1a 4a aa 63 32 45 f2 9f be ab 36 51 51 c3 f9 cd fc dc 37 4b 50 77 aa 5e e3 22 49 e3 c6 00 71 a2 01 41 04 b8 77 81 89 c9 15 eb 35 33 93 f9 fb b0 1c 3b 50 a2 63 fa 69 f6 4f 5e 30 d7 86 bb a3 b7 93 96 b6 64 66 83 c1 a5 2d d5 be 12 0d 5a 3b 6b db 87 87 5e 8a 96 34 d9 80 b0 d8 b3 0b 70 91 3b 40 3a 58 ff ff ff ff 4e 02 01 88 16 42 6d 02 29 94 71 2b 57 4d d2 18 ed 99 a6 b5 22 68 b6 91 b3 80 09 17 12 fd 5d 17 18 00 00 00 8c 49 30 46 02 21 00 90 9e f4 7b 31 38 49 0e 12 9d 93 2e ed c3 de 6d df 67 c5 8b d0 a5 4d 75 e9 15 b3 1b 79 3c 83 08 02 21 00 8b fa 4b 84 c9 32 38 0b e3 56 1f d4 d4 dc d6 8d bf 00 b8 b4 0a a6 05 63 07 02 cb fe e1 a4 40 c7 01 41 04 83 c5 d3 b9 eb 6a 4b 6f 18 12 ed e4 2f 7d 86 72 6f 9a a0 bb b1 a2 5d 76 04 bb c6 32 c0 93 b0 d4 7a 23 26 32 52 ff bb d2 99 5c a1 da 2f bb b6 c6 42 ea aa 75 ea e2 63 10 b2 0a ec 04 49 3a fa 1a ff ff ff ff 02 40 42 0f 00 00 00 00 00 19 76 a9 14 31 29 d7 05 1d 50 94 24 d2 3d 53 3f a2 d5 25 89 77 e8 22 e3 88 ac 00 c2 eb 0b 00 00 00 00 19 76 a9 14 f3 de 26 ff 7d 47 2d 53 65 e3 ad af ec e9 bb dc ac e9 15 a0 88 ac 00 00 00 00"
      .split(" ").join].pack("H*")[24..-1],
  ]



  it '#new' do
    proc{
      Bitcoin::Protocol::Tx.new( nil )
      @payload.each{|payload| Bitcoin::Protocol::Tx.new( payload ) }
    }.should.not.raise Exception

    proc{
      Bitcoin::Protocol::Tx.new( @payload[0][0..20] )
    }.should.raise Exception
  end

  it '#parse_data' do
    tx = Bitcoin::Protocol::Tx.new( nil )

    tx.hash.should == nil
    tx.parse_data( @payload[0] ).should == true
    tx.hash.size.should == 64

    tx = Bitcoin::Protocol::Tx.new( nil )
    tx.parse_data( @payload[0] + "AAAA" ).should == "AAAA"
    tx.hash.size.should == 64
  end

  it '#hash' do
    tx = Bitcoin::Protocol::Tx.new( @payload[0] )
    tx.hash.size.should == 64
    tx.hash.should == "6e9dd16625b62cfcd4bf02edb89ca1f5a8c30c4b1601507090fb28e59f2d02b4"
  end

  it '#to_json' do
    tx = Bitcoin::Protocol::Tx.new( @payload[0] )
    tx.to_json.should == (<<-TEXT).chomp
{
  "hash": "6e9dd16625b62cfcd4bf02edb89ca1f5a8c30c4b1601507090fb28e59f2d02b4",
  "ver": 1,
  "vin_sz": 1,
  "vout_sz": 2,
  "lock_time": 0,
  "size": 258,
  "in": [
    {
      "prev_out": {
        "hash": "c866fc2aea0e36ce632886f26a66487ba751762d0f085763d01efc438336f6b0",
        "n": 0
      },
      "scriptSig": "3045022100bde2e702380813d61069845a75e330779bbacc6a1330bd9dfd1fec1bd94f8f17022075c29d9b37957c80068436609755942be0f7f6fbd30983a557a6e0640edeeb1601 049de89dd4f0b3801c2d28a334f0fb8b0bfd7a9d67530e9dffa536bd7130e8dfd32a01e7bafcdd956fdeece0f341fa4f2727890bf09fe0dd1dea9169aad9c30242"
    }
  ],
  "out": [
    {
      "value": "0.24956381",
      "scriptPubKey": "76a914b2e21c1db922e3bdc529de7b38b4c401399e9afd88ac"
    },
    {
      "value": "0.03993619",
      "scriptPubKey": "76a9147766347a890638dc3cd8d4ef99b8e40c6519d11e88ac"
    }
  ]
}
    TEXT

    tx = Bitcoin::Protocol::Tx.new( @payload[1] )
    tx.to_json.should == (<<-TEXT).chomp
{
  "hash": "e6d0a1bc0355e4208c606cb3ae1f047875c13f966c6c861a154e2fe61a4132a5",
  "ver": 1,
  "vin_sz": 1,
  "vout_sz": 2,
  "lock_time": 0,
  "size": 258,
  "in": [
    {
      "prev_out": {
        "hash": "0abe13b3a6e01b12ec7abc592328d5edd5e9029d7d9ee9cd1440382812953ee1",
        "n": 0
      },
      "scriptSig": "304502207442f42bb0c64f948df0711ae61e8612a011d83e755507d73c8cf6b1ae71fcd5022100a61a91f426a20db8778e35d14792f64daa0e8edf2acd5a9329adc25e0074a2cf01 045833aa1677dc0f5bd773b835622d53b4d31bc194577290a48897fb157e6af925bec9ce0dad4fc9e613d9d4661d78c111b02f219ca446e0c101b730d1234c4978"
    }
  ],
  "out": [
    {
      "value": "127.81000000",
      "scriptPubKey": "76a9147bc2e19b0afd1c78ec792bbad334d41db2da884588ac"
    },
    {
      "value": "0.33000000",
      "scriptPubKey": "76a914ffad3e6ddcfdb412953d41887a21e9ff9805a93c88ac"
    }
  ]
}
    TEXT

    tx = Bitcoin::Protocol::Tx.new( @payload[2] )
    tx.to_json.should == (<<-TEXT).chomp
{
  "hash": "56577828eace17d718e538d51f3122bc7193bf37879b8a9d6638c4c5101159bc",
  "ver": 1,
  "vin_sz": 4,
  "vout_sz": 2,
  "lock_time": 0,
  "size": 798,
  "in": [
    {
      "prev_out": {
        "hash": "1f130699a1eb657f4eb051865ef4399dcaf8a34d5bbff879107829e687acf865",
        "n": 0
      },
      "scriptSig": "3045022100fd9d06ec1b74060a6e85e2ff614d4cf01c41a30debd86ac669ee5370b038a29302204ce4595ea7658ba2a1487aa784ed7543d0b394b0393d732a3ea4f247ffd7f49301 04974deddf7b6dbfdbe6799f58b4460b0f80e609d52d5ab13c398b8456c8dd9ea29fc6702a69edfe76bd2b7e7361e0a81523cba342133ed0e270b2d38e51429a33"
    },
    {
      "prev_out": {
        "hash": "d9fe5ba4752e3b7dd1c0fceaaa3124c73eef34d8dc2a0bf8e6dc6e9413556f84",
        "n": 0
      },
      "scriptSig": "304502210096782e8d62ec98f14b51639a0aa04588f847ea124d9709d2e48ec649d562ed0602203d5a6fec66af2518960bdbaf556d10732882ad9563d8ec38c22a1668306a5acf01 04b65a4e775c8d55676ddd25f97236c6b452b5ab986e2ed7562db453ebce7c95badfb890e0da2653747a21b463c63eb8ba6ab9ff9ce268a3600c1b906d5e295695"
    },
    {
      "prev_out": {
        "hash": "d634f4d77f0f407077e6b11168c33d7d17c18d8c962dcc14b5ca2fc4a4e1efcf",
        "n": 0
      },
      "scriptSig": "3044022025c899f50e42b79a258d10a941e61529d4ad1e1d5dfd891ee243a186fbbbf81f02201a4aaa633245f29fbeab365151c3f9cdfcdc374b5077aa5ee32249e3c60071a201 04b8778189c915eb353393f9fbb01c3b50a263fa69f64f5e30d786bba3b79396b6646683c1a52dd5be120d5a3b6bdb87875e8a9634d980b0d8b30b70913b403a58"
    },
    {
      "prev_out": {
        "hash": "175dfd12170980b391b66822b5a699ed18d24d572b719429026d42168801024e",
        "n": 24
      },
      "scriptSig": "3046022100909ef47b3138490e129d932eedc3de6ddf67c58bd0a54d75e915b31b793c83080221008bfa4b84c932380be3561fd4d4dcd68dbf00b8b40aa605630702cbfee1a440c701 0483c5d3b9eb6a4b6f1812ede42f7d86726f9aa0bbb1a25d7604bbc632c093b0d47a23263252ffbbd2995ca1da2fbbb6c642eaaa75eae26310b20aec04493afa1a"
    }
  ],
  "out": [
    {
      "value": "0.01000000",
      "scriptPubKey": "76a9143129d7051d509424d23d533fa2d5258977e822e388ac"
    },
    {
      "value": "2.00000000",
      "scriptPubKey": "76a914f3de26ff7d472d5365e3adafece9bbdcace915a088ac"
    }
  ]
}
    TEXT
  end

end
