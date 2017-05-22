# encoding: ascii-8bit

require_relative 'spec_helper'

# BIP-32 test
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors
describe Bitcoin::ExtKey do

  describe 'Test Vector 1' do

    before do
      Bitcoin.network = :bitcoin
      @master_key = Bitcoin::ExtKey.generate_master('000102030405060708090a0b0c0d0e0f'.htb)
    end

    it 'Chain m' do
      @master_key.depth.should == 0
      @master_key.number.should == 0
      @master_key.fingerprint.should == '3442193e'
      @master_key.chain_code.bth.should == '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508'
      @master_key.priv.should == 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35'
      @master_key.addr.should == '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma'
      @master_key.pub.should == '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2'
      @master_key.to_base58.should == 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
      @master_key.ext_pubkey.to_base58.should == 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
      @master_key.ext_pubkey.pub.should == '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2'
      @master_key.ext_pubkey.addr.should == '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma'
    end

    it 'Chain m/0H' do
      key = @master_key.derive(2**31)
      key.depth.should == 1
      key.fingerprint.should == '5c1bd648'
      key.chain_code.bth.should == '47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141'
      key.priv_key.priv.should == 'edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea'
      key.to_base58.should == 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'
      key.ext_pubkey.to_base58.should == 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw'
    end

    it 'Chain m/0H/1' do
      key = @master_key.derive(2**31).derive(1)
      key.depth.should == 2
      key.fingerprint.should == 'bef5a2f9'
      key.chain_code.bth.should == '2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19'
      key.priv_key.priv.should == '3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368'
      key.to_base58.should == 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'
      key.ext_pubkey.to_base58.should == 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'

      # pubkey derivation
      ext_pubkey = @master_key.derive(2**31).ext_pubkey.derive(1)
      ext_pubkey.to_base58.should == 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'
    end

    it 'Chain m/0H/1/2H' do
      key = @master_key.derive(2**31).derive(1).derive(2**31 + 2)
      key.depth.should == 3
      key.fingerprint.should == 'ee7ab90c'
      key.chain_code.bth.should == '04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f'
      key.priv_key.priv.should == 'cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca'
      key.to_base58.should == 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'
      key.ext_pubkey.to_base58.should == 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5'
    end

    it 'Chain m/0H/1/2H/2' do
      key = @master_key.derive(2**31).derive(1).derive(2**31 + 2).derive(2)
      key.depth.should == 4
      key.fingerprint.should == 'd880d7d8'
      key.chain_code.bth.should == 'cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd'
      key.priv_key.priv.should == '0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4'
      key.to_base58.should == 'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'
      key.ext_pubkey.to_base58.should == 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV'
    end

    it 'Chain m/0H/1/2H/2/1000000000' do
      key = @master_key.derive(2**31).derive(1).derive(2**31 + 2).derive(2).derive(1000000000)
      key.depth.should == 5
      key.fingerprint.should == 'd69aa102'
      key.chain_code.bth.should == 'c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e'
      key.priv_key.priv.should == '471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8'
      key.to_base58.should == 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'
      key.ext_pubkey.to_base58.should == 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy'
    end
  end

  describe 'Test Vector 2' do
    before do
      Bitcoin.network = :bitcoin
      @master_key = Bitcoin::ExtKey.generate_master('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'.htb)
    end

    it 'Chain m' do
      @master_key.depth.should == 0
      @master_key.number.should == 0
      @master_key.to_base58.should == 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U'
      @master_key.ext_pubkey.to_base58.should == 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
    end

    it 'Chain m/0' do
      key = @master_key.derive(0)
      key.depth.should == 1
      key.number.should == 0
      key.to_base58.should == 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'
      key.ext_pubkey.to_base58.should == 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH'
    end

    it 'Chain m/0/2147483647H' do
      key = @master_key.derive(0).derive(2**31 + 2147483647)
      key.depth.should == 2
      key.number.should == 2**31 + 2147483647
      key.to_base58.should == 'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9'
      key.ext_pubkey.to_base58.should == 'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a'
    end

    it 'Chain m/0/2147483647H/1' do
      key = @master_key.derive(0).derive(2**31 + 2147483647).derive(1)
      key.depth.should == 3
      key.number.should == 1
      key.to_base58.should == 'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef'
      key.ext_pubkey.to_base58.should == 'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon'
    end

    it 'Chain m/0/2147483647H/1/2147483646H' do
      key = @master_key.derive(0).derive(2**31 + 2147483647).derive(1).derive(2**31 + 2147483646)
      key.depth.should == 4
      key.number.should == 2**31 + 2147483646
      key.to_base58.should == 'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc'
      key.ext_pubkey.to_base58.should == 'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL'
    end

    it 'Chain m/0/2147483647H/1/2147483646H/2' do
      key = @master_key.derive(0).derive(2**31 + 2147483647).derive(1).derive(2**31 + 2147483646).derive(2)
      key.depth.should == 5
      key.number.should == 2
      key.to_base58.should == 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j'
      key.ext_pubkey.to_base58.should == 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt'
      ext_pubkey = @master_key.derive(0).derive(2**31 + 2147483647).derive(1).derive(2**31 + 2147483646).ext_pubkey.derive(2)
      ext_pubkey.to_base58.should == 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt'
    end

  end

  describe 'import from base58 address' do

    it 'import private key' do
      # normal key
      key = Bitcoin::ExtKey.from_base58('xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs')
      key.depth.should == 2
      key.number.should == 1
      key.chain_code.bth.should == '2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19'
      key.priv_key.priv.should == '3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368'
      key.ext_pubkey.to_base58.should == 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'

      # hardended key
      key = Bitcoin::ExtKey.from_base58('xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM')
      key.depth.should == 3
      key.number.should == 2**31 + 2
      key.fingerprint.should == 'ee7ab90c'
      key.chain_code.bth.should == '04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f'
      key.priv_key.priv.should == 'cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca'
      key.to_base58.should == 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'
      key.ext_pubkey.to_base58.should == 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5'
    end

    it 'import public key' do
      # normal key
      key = Bitcoin::ExtPubkey.from_base58('xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')
      key.depth.should == 2
      key.number.should == 1
      key.chain_code.bth.should == '2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19'
      key.to_base58.should == 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'

      # hardended key
      key = Bitcoin::ExtPubkey.from_base58('xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5')
      key.depth.should == 3
      key.number.should == 2**31 + 2
      key.fingerprint.should == 'ee7ab90c'
      key.chain_code.bth.should == '04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f'
    end
  end
end