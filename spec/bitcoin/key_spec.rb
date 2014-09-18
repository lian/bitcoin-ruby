# encoding: ascii-8bit

require_relative 'spec_helper'

describe "Bitcoin::Key" do

  before do
    Bitcoin.network = :bitcoin
    @key_data = {
      :priv => "2ebd3738f59ae4fd408d717bf325b4cb979a409b0153f6d3b4b91cdfe046fb1e",
      :pub => "035fcb2fb2802b024f371cc22bc392268cc579e47e7936e0d1f05064e6e1103b8a" }
    @key = Bitcoin::Key.new(@key_data[:priv], @key_data[:pub], false)
  end

  it "should generate a key" do
    k = Bitcoin::Key.generate
    k.priv.size.should == 64
    k.pub.size.should == 66
    k.compressed.should == true

    k = Bitcoin::Key.generate(compressed: true)
    k.priv.size.should == 64
    k.pub.size.should == 66
    k.compressed.should == true

    k = Bitcoin::Key.generate(true)
    k.priv.size.should == 64
    k.pub.size.should == 66
    k.compressed.should == true

    k = Bitcoin::Key.generate(compressed: false)
    k.priv.size.should == 64
    k.pub.size.should == 130
    k.compressed.should == false

    k = Bitcoin::Key.generate(false)
    k.priv.size.should == 64
    k.pub.size.should == 130
    k.compressed.should == false
  end

  it "should create empty key" do
    k = Bitcoin::Key.new
    k.priv.should == nil
    k.pub.should == nil
    k.compressed.should == true
  end

  it "should create key from priv + pub" do
    k = Bitcoin::Key.new(@key_data[:priv], @key_data[:pub])
    k.priv.should == @key_data[:priv]
    k.pub.should == @key_data[:pub]
  end

  it "should create key from only priv" do
    k = Bitcoin::Key.new(@key_data[:priv])
    k.priv.should == @key_data[:priv]
    k.pub.should == @key_data[:pub]
  end

  it "should create key from only pub" do
    k = Bitcoin::Key.new(nil, @key_data[:pub])
    k.pub.should == @key_data[:pub]
  end

  it "should set public key" do
    k = Bitcoin::Key.new
    k.pub = @key_data[:pub]
    k.pub.should == @key_data[:pub]
  end

  it "should set private key" do
    k = Bitcoin::Key.new
    k.priv = @key_data[:priv]
    k.priv.should == @key_data[:priv]
    k.pub.should == @key_data[:pub]
  end

  it "should get addr" do
    @key.addr.should == "19CyxBz6CUBogxTdSXUrbRHo7T7eLCMgbr"
    @key.instance_eval { @pubkey_compressed = false }
    @key.addr.should == "1JbYZRKyysprVjSSBobs8LX6QVjzsscQNU"
  end

  it "should sign data" do
    @key.sign("foobar").size.should >= 69
  end

  it "should verify signature using public key" do
    sig = @key.sign("foobar")
    key = Bitcoin::Key.new(nil, @key.pub)
    key.verify("foobar", sig).should == true
  end

  it "should verify signature using private key" do
    sig = @key.sign("foobar")
    key = Bitcoin::Key.new(@key.priv)
    key.verify("foobar", sig).should == true
  end

  it "recovers public keys from compact signatures" do
    tests = [
        # normal
      { address: "16vqGo3KRKE9kTsTZxKoJKLzwZGTodK3ce",
        signature: "HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDFORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50=",
        message: "test message",
        expected: true },

        # different message
      { address: "16vqGo3KRKE9kTsTZxKoJKLzwZGTodK3ce",
        signature: "HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDFORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50=",
        message: "not what I signed",
        expected: false },

        # different address
      { address: "1JbYZRKyysprVjSSBobs8LX6QVjzsscQNU",
        signature: "HPDs1TesA48a9up4QORIuub67VHBM37X66skAYz0Esg23gdfMuCTYDFORc6XGpKZ2/flJ2h/DUF569FJxGoVZ50=",
        message: "test message",
        expected: false },

        # compressed
      { address: "18uitB5ARAhyxmkN2Sa9TbEuoGN1he83BX",
        signature: "IMAtT1SjRyP6bz6vm5tKDTTTNYS6D8w2RQQyKD3VGPq2i2txGd2ar18L8/nvF1+kAMo5tNc4x0xAOGP0HRjKLjc=",
        message: "testtest",
        expected: true },
      ]
    tests.each do |test|
      key = Bitcoin::Key.recover_compact_signature_to_key(test[:message], test[:signature])
      test[:expected].should == (key.addr == test[:address])
    end
  end

  it "should export private key in base58 format" do
    Bitcoin.network = :bitcoin
    str = Bitcoin::Key.new("e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262", nil, false).to_base58
    str.should == "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF"
    Bitcoin.network = :testnet
    str = Bitcoin::Key.new("d21fa2c7ad710ffcd9bcc22a9f96357bda1a2521ca7181dd610140ecea2cecd8", nil, false).to_base58
    str.should == "93BTVFoqffueSaC5fqjLjLyn29S41JzvAZm2hC35SYMoYDXT1bY"
    Bitcoin.network = :bitcoin
  end

  it "should import private key in base58 format" do
    Bitcoin.network = :bitcoin
    key = Bitcoin::Key.from_base58("5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF")
    key.priv.should == "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262"
    key.addr.should == "1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj"
    Bitcoin.network = :testnet
    key = Bitcoin::Key.from_base58("93BTVFoqffueSaC5fqjLjLyn29S41JzvAZm2hC35SYMoYDXT1bY")
    key.priv.should == "d21fa2c7ad710ffcd9bcc22a9f96357bda1a2521ca7181dd610140ecea2cecd8"
    key.addr.should == "n3eH91H14mSnGx4Va2ngtLFCeLPRyYymRg"
    Bitcoin.network = :bitcoin
  end

  it "should export private key in compressed base58 format" do
    Bitcoin.network = :bitcoin
    Bitcoin::Key.new("98e4483a197fb686fe9afb51389f329aabc67964b1d0e0a5340c962a0d63c44a",
      nil, true).to_base58.should == "L2LusdhGSagfUVvNWrUuPDygn5mdAhxUDEANfABvBj36Twn1mKgQ"
    Bitcoin.network = :testnet3
    Bitcoin::Key.new("e3ff5d7e592669d0c1714f1496b260815edd0c3a00186e896dc7f36ede914dd2",
      nil, true).to_base58.should == "cVDu6aXUWHTM2vpztZW14BMnKkCcd5th6177VnCsa8XozoMyp73C"
    Bitcoin.network = :bitcoin
  end

  it "should import private key in compressed base58 format" do
    Bitcoin.network = :bitcoin
    key = Bitcoin::Key.from_base58("L2LusdhGSagfUVvNWrUuPDygn5mdAhxUDEANfABvBj36Twn1mKgQ")
    key.priv.should == "98e4483a197fb686fe9afb51389f329aabc67964b1d0e0a5340c962a0d63c44a"
    key.pub.should == "02e054ee811165ac294c992ff410067db6491228725fe09db2a415493c897973a8"
    key.compressed.should == true
    key.addr.should == "1C7Ni4zuV3zfLs8T1S7s29wNAtRoDHHnpw"
    Bitcoin.network = :testnet3
    key = Bitcoin::Key.from_base58("cVDu6aXUWHTM2vpztZW14BMnKkCcd5th6177VnCsa8XozoMyp73C")
    key.priv.should == "e3ff5d7e592669d0c1714f1496b260815edd0c3a00186e896dc7f36ede914dd2"
    key.pub.should == "0390bb61c062266a1e8460ec902379749ae30f569013d82bd448a61591f20b8ee2"
    key.addr.should == "mjh9RgZh14FfJQ2pFpRSqEQ5BH1nHo5To7"
    Bitcoin.network = :bitcoin
  end

  it "should handle compressed and uncompressed pubkeys" do
    compressed   = "0351efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477da78"
    uncompressed = "0451efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477da787f71a2e8ac5aacedab47904d4bd42f636429e9ce069ebcb99f675aad31306a53"
    Bitcoin::Key.new(nil, compressed).compressed.should == true
    Bitcoin::Key.new(nil, compressed).pub.should  == compressed
    Bitcoin::Key.new(nil, compressed).addr.should == "1NdB761LmTmrJixxp93nz7pEiCx5cKPW44"
    Bitcoin::Key.new(nil, uncompressed).compressed.should == false
    Bitcoin::Key.new(nil, uncompressed).pub.should == uncompressed
    Bitcoin::Key.new(nil, uncompressed).addr.should == "19FBCg9295EBQ4P6bSLTGyz2BdbbPcqQD"

    key = Bitcoin::Key.new(nil, compressed)
    key.pub_compressed.should   == compressed
    key.pub_uncompressed.should == uncompressed

    sig = @key.sign(msg="foobar")
    Bitcoin::Key.new(nil, @key.pub_compressed  ).verify(msg, sig).should == true
    Bitcoin::Key.new(nil, @key.pub_uncompressed).verify(msg, sig).should == true

    compressed   = "02f01984446a994a9e422c9ba9c6f33f1f40c01d9d872064a49679d702fae33064"
    Bitcoin::Key.new(nil, compressed).pub.should  == compressed
    Bitcoin::Key.new(nil, compressed).addr.should == "18TWywxjESkg4pzJqBYNDo39S2QMPaWWJ5"

    k = Bitcoin::Key.new(nil, nil)
    k.instance_eval{ set_pub("02f01984446a994a9e422c9ba9c6f33f1f40c01d9d872064a49679d702fae33064") }
    k.compressed.should == true

    k = Bitcoin::Key.new(nil, nil)
    k.instance_eval{ set_pub("0351efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477da78") }
    k.compressed.should == true

    k = Bitcoin::Key.new(nil, nil)
    k.instance_eval{ set_pub("0451efb6e91a31221652105d032a2508275f374cea63939ad72f1b1e02f477da787f71a2e8ac5aacedab47904d4bd42f636429e9ce069ebcb99f675aad31306a53") }
    k.compressed.should == false
  end

  it "should handle private key in bip38 (non-ec-multiply) format" do
    k = Bitcoin::Key.from_base58("5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR")
    k.to_bip38("TestingOneTwoThree").should == "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"

    k = Bitcoin::Key.from_bip38("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg", "TestingOneTwoThree")
    k.to_base58.should == "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR"

    k = Bitcoin::Key.from_base58("5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5")
    k.to_bip38("Satoshi").should == "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq"

    k = Bitcoin::Key.from_bip38("6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq", "Satoshi")
    k.to_base58.should == "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5"

    k = Bitcoin::Key.from_base58("L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP")
    k.to_bip38("TestingOneTwoThree").should == "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo"

    k = Bitcoin::Key.from_bip38("6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo", "TestingOneTwoThree")
    k.to_base58.should == "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP"

    k = Bitcoin::Key.from_base58("KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7")
    k.to_bip38("Satoshi").should == "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7"

    k = Bitcoin::Key.from_bip38("6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7", "Satoshi")
    k.to_base58.should == "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7"
  end

  it "should generate private key from warp format" do
    k = Bitcoin::Key.from_warp("ER8FT+HFjk0", "7DpniYifN6c")
    k.addr.should == "1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ"
    k.to_base58.should == "5JfEekYcaAexqcigtFAy4h2ZAY95vjKCvS1khAkSG8ATo1veQAD"

    k = Bitcoin::Key.from_warp("YqIDBApDYME", "G34HqIgjrIc")
    k.addr.should == "19aKBeXe2mi4NbQRpYUrCLZtRDHDUs9J7J"
    k.to_base58.should == "5KUJA5iZ2zS7AXkU2S8BiBVY3xj6F8GspLfWWqL9V7CajXumBQV"

    k = Bitcoin::Key.from_warp("FPdAxCygMJg", "X+qaSwhUYXw")
    k.addr.should == "14Pqeo9XNRxjtKFFYd6TvRrJuZxVpciS81"
    k.to_base58.should == "5JBAonQ4iGKFJxENExZghDtAS6YB8BsCw5mwpHSvZvP3Q2UxmT1"
  end

end

begin
  describe "Bitcoin::OpenSSL_EC" do
    Bitcoin::OpenSSL_EC

    it 'resolves public from private key' do
      privkey = ["56e28a425a7b588973b5db962a09b1aca7bdc4a7268cdd671d03c52a997255dc"].pack("H*")
      pubkey =  ["04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030eaa1552e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3"].pack("H*")

      Bitcoin::OpenSSL_EC.regenerate_key(privkey).should == [privkey, pubkey].map{|i| i.unpack("H*")[0] }

      [
        ["b51386f8275d49d8d30287d7b1afa805790bdd1fe8b13d22d25928c67ea55d02", "0470305ae5278a22499980286d9c513861d89e7b7317c8b891c554d5c8fdd256b03daa0340be4104f8c84cfa98f0da8f16567fcdd3a00fd993adbbe91695671a56"],
        ["d8ebece51adc5fb99dd6994bcb8fa1221d01576fd76af9134ab36f8d4698b55c", "047503421850d3a6eecb7c9de33b367c4d3f96a34ff257ad0c34e234e29f3672525c6b4353ce6fdc9de3f885fdea798982e2252e610065dbdb62cd8cab1fe45822"],
        ["c95c79fb0cc1fe47b384751df0627be40bbe481ec94eeafeb6dc40e94c40de43", "04b746ca07e718c7ca26d4eeec037492777f48bb5c750e972621698f699f530535c0ffa96dad581102d0471add88e691af85955d1fd42f68506f8092fddfe0c47a"],
        ["5b61f807cc938b0fd3ec8f6006737d0002ceca09f296204138c4459de8a856f6", "0487357bf30c13d47d955666f42f87690cfd18be96cc74cda711da74bf76b08ebc6055aba30680e6288df14bda68c781cbf71eaad096c3639e9724c5e26f3acf54"]
      ].each{|key|
        privkey, pubkey = [ key.first ].pack("H*")
        Bitcoin::OpenSSL_EC.regenerate_key(privkey).should == key
      }

      250.times.map{
        keypair = Bitcoin.generate_key;
        Bitcoin::OpenSSL_EC.regenerate_key(keypair.first) == keypair
      }.all?.should == true
    end

    it 'recover public key from compact signature' do
      args = [
              "\x12&\x17\x9D\xDFc\x83\xFB\xCFQ\x02\xC9I%8\xB7 ls\x9A\xE7\x9E\xB0d@\x8C*\xBDg\xD3\x9B\xED",
              "\x1C\xF0\xEC\xD57\xAC\x03\x8F\x1A\xF6\xEAx@\xE4H\xBA\xE6\xFA\xEDQ\xC13~\xD7\xEB\xAB$\x01\x8C\xF4\x12\xC86\xDE\a_2\xE0\x93`1NE\xCE\x97\x1A\x92\x99\xDB\xF7\xE5'h\x7F\rAy\xEB\xD1I\xC4j\x15g\x9D",
              1, false
             ]
      expected = "047840b97f46d4c32c62119f9e069172272592ec7741a3aec81e339b87387350740dce89837c8332910f349818060b66070b94e8bb11442d49d3f6c0d7f31ba6a6"

      # 10_000.times{|n| # enable for memory leak testing
      #   puts 'RAM USAGE: ' + `pmap #{Process.pid} | tail -1`[10,40].strip if (n % 1_000) == 0
        Bitcoin::OpenSSL_EC.recover_public_key_from_signature(*args).should == expected
      # }
    end

    it 'sign and verify text messages' do
      [
        ["5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj", false],
        ["5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3", false],
        ["Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw", true],
        ["L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g", true],
      ].each{|privkey_base58,expected_compression|
        k = Bitcoin::Key.from_base58(privkey_base58)
        k.compressed.should == expected_compression
        k2 = Bitcoin::Key.new(nil, k.pub)
        k2.compressed.should == expected_compression
        16.times{|n|
          msg = "Very secret message %d: 11" % n
          signature = k.sign_message(msg)
          k2.verify_message(signature, msg).should == true
          Bitcoin::Key.verify_message(k.addr, signature, msg).should == true
        }
      }
    end

  end
rescue LoadError
end
