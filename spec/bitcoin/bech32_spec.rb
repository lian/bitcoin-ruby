# encoding: ascii-8bit

require_relative 'spec_helper'

describe Bitcoin::Bech32 do
  before do
    Bitcoin.network = :bitcoin

    @invalid_address_enc = [
      ["BC", 0, 20],
      ["bc", 0, 21],
      ["bc", 17, 32],
      ["bc", 1, 1],
      ["bc", 16, 41],
    ]

    @valid_address = [
        [
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            22, [
                0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
            ]
        ],
        [
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            34, [
                0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
                0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
                0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
                0x62
            ]
        ],
        [
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
            42, [
                0x51, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
                0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
                0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
            ]
        ],
        [
            "BC1SW50QA3JX3S",
            4, [
               0x60, 0x02, 0x75, 0x1e
            ]
        ],
        [
            "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
            18, [
                0x52, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23
            ]
        ],
        [
            "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            34, [
                0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
                0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
                0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
                0x33
            ]
        ]
    ]

		@valid_checksum = [
				"A12UEL5L",
				"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
				"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
				"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
				"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
		]

		@invalid_checksum = [
				" 1nwldj5",
				"\x7f""1axkwrx",
				"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
				"pzry9x0s0muk",
				"1pzry9x0s0muk",
				"x1b4n0q5v",
				"li1dgmt3",
				"de1lg7wt\xff",
		]

		@invalid_address = [
				"tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
				"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
				"BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
				"bc1rw5uspcuh",
				"bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
				"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
				"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
				"bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
				"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
				"bc1gmk9yu",
		]
  end

  describe '#decode and #encode' do
    it "test vectors" do
      @valid_checksum.each do |testdata|
        hrp, data = Bitcoin::Bech32.decode(testdata)
        newdata = Bitcoin::Bech32.encode(hrp, data)
        newdata.should == testdata.downcase
      end

      @invalid_checksum.each do |testdata|
        hrp, data = Bitcoin::Bech32.decode(testdata)
        hrp.should == nil
      end

      @valid_address.each do |testdata, _, _|
        hrp, data = Bitcoin::Bech32.decode(testdata)
        newdata = Bitcoin::Bech32.encode(hrp, data)
        newdata.should == testdata.downcase
      end
    end
  end

  describe '#decode_segwit_address and #encode_segwit_address' do
    it "test vectors" do
			@valid_address.each do |testaddress, _, testscript|
				Bitcoin.network = :bitcoin
				version, program = Bitcoin.decode_segwit_address(testaddress)
				if version.nil?
					Bitcoin.network = :testnet3
					version, program = Bitcoin.decode_segwit_address(testaddress)
				end
				version.should != nil

        script = Bitcoin::Script.to_witness_script(version, program)
        script.should == testscript.pack("C*")

        newaddress = Bitcoin.encode_segwit_address(version, program)
        newaddress.should != nil
        newaddress.should == testaddress.downcase
			end

			@invalid_address.each do |testaddress|
				Bitcoin.network = :bitcoin
				version, program = Bitcoin.decode_segwit_address(testaddress)
				if version.nil?
					Bitcoin.network = :testnet3
					version, program = Bitcoin.decode_segwit_address(testaddress)
				end
				version.should == nil
      end

			Bitcoin.network = :bitcoin
      @invalid_address_enc.each do |testhrp, testversion, testlength|
			  Bitcoin.network[:bech32_hrp] = testhrp
        program_hex = Array.new(testlength){ 0 }.pack("C*").unpack("H*").first
        newaddress = Bitcoin.encode_segwit_address(testversion, program_hex)
        newaddress.should == nil
      end
    end
  end

end
