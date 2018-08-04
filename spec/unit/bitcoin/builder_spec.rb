# frozen_string_literal: true

require 'spec_helper'

describe Bitcoin::Builder do
  let(:keys) { Array.new(5) { Bitcoin::Key.generate } }
  let(:target) { '00'.ljust(64, 'f') }
  let(:genesis_block) { create_block('00' * 32, false) }
  let(:block) { create_block(genesis_block.hash, false, [], keys[0]) }

  before { Bitcoin.network = :spec }

  it 'should build blocks' do
    result = build_block(target) do |b|
      b.prev_block block.hash

      b.tx do |t|
        t.input { |i| i.coinbase 'foobar' }

        t.output do |o|
          o.value 5_000_000_000

          o.script do |s|
            s.type :address
            s.recipient keys[0].addr
          end
        end
      end
    end

    expect(result.hash[0..1]).to eq('00')
    expect(result.ver).to eq(1)
    expect(result.prev_block).to eq(block.binary_hash.reverse)
    expect(result.tx.size).to eq(1)

    tx = result.tx[0]
    expect(tx.in.size).to eq(1)
    expect(tx.out.size).to eq(1)
    expect(tx.in[0].script_sig).to eq(['foobar'].pack('H*'))
    expect(tx.out[0].value).to eq(5_000_000_000)
  end

  it 'should build transactions with input and output signatures' do
    tx = build_tx do |t|
      t.input do |i|
        i.prev_out block.tx[0]
        i.prev_out_index 0
        i.signature_key keys[0]
      end

      t.output do |o|
        o.value 123

        o.script do |s|
          s.type :address
          s.recipient keys[1].addr
        end
      end
    end

    expect(tx.in[0].prev_out.reverse_hth).to eq(block.tx[0].hash)
    expect(tx.in[0].prev_out_index).to eq(0)
    expect(
      Bitcoin::Script.new(tx.in[0].script_sig).chunks[1].unpack('H*')[0]
    ).to eq(keys[0].pub)

    expect(tx.out[0].value).to eq(123)
    script = Bitcoin::Script.new(tx.out[0].pk_script)
    expect(script.type).to eq(:hash160)
    expect(script.get_address).to eq(keys[1].addr)

    expect(tx.verify_input_signature(0, block.tx[0])).to be true

    # check shortcuts also work
    tx2 = build_tx do |t|
      t.input do |i|
        i.prev_out block.tx[0], 0
        i.signature_key keys[0]
      end
      t.output do |o|
        o.value 123
        o.script { |s| s.recipient keys[1].addr }
      end
      t.output do |o|
        o.to keys[1].addr
        o.value 321
      end
      t.output { |o| o.to 'deadbeef', :op_return }
    end

    expect(tx2.in[0].prev_out).to eq(tx.in[0].prev_out)
    expect(tx2.in[0].prev_out_index).to eq(tx.in[0].prev_out_index)
    expect(tx2.out[0].value).to eq(tx.out[0].value)
    expect(tx2.out[0].pk_script).to eq(tx.out[0].pk_script)

    expect(
      Bitcoin::Script.new(tx2.out[0].pk_script).to_string
    ).to eq(
      "OP_DUP OP_HASH160 #{keys[1].hash160} OP_EQUALVERIFY OP_CHECKSIG"
    )
    expect(
      Bitcoin::Script.new(tx2.out[0].pk_script).to_string
    ).to eq(
      "OP_DUP OP_HASH160 #{keys[1].hash160} OP_EQUALVERIFY OP_CHECKSIG"
    )
    expect(tx2.out[2].value).to eq(0)
  end

  it 'should build transactions with p2wpkh signatures' do
    key = Bitcoin::Key.new('619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9')
    script_pubkey = '00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1'.htb

    tx = build_tx do |t|
      t.input do |i|
        i.prev_out(
          '8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef',
          1,
          script_pubkey,
          600_000_000
        )
        i.signature_key key
      end
    end

    expect(
      tx.verify_witness_input_signature(0, script_pubkey, 600_000_000)
    ).to be true
    expect(tx.in[0].script_sig).to eq('')
  end

  it 'should failure to build tx with p2wpkh signatures due to inconsistency of key' do
    key = Bitcoin::Key.new('619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9')
    script_pubkey = '0014deadbeafdeadbeafdeadbeafdeadbeafdeadbeaf'.htb

    expect do
      build_tx do |t|
        t.input do |i|
          i.prev_out(
            '8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef',
            1,
            script_pubkey,
            600_000_000
          )
          i.signature_key key
        end
      end
    end.to raise_error(RuntimeError, 'Signature error')
  end

  it 'should build p2sh transaction with p2wpkh signatures' do
    key = Bitcoin::Key.new('619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9')
    witness_prog = '00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1'.htb
    script_pubkey = Bitcoin::Script.to_p2sh_script('bdbb096c26dd64dca06d0fbe8bb5e990ac3cdb42')
    tx = build_tx do |t|
      t.input do |i|
        i.prev_out(SecureRandom.hex(32), 0, script_pubkey, 600_000_000)
        i.redeem_script witness_prog
        i.signature_key key
      end
    end

    expect(
      tx.verify_witness_input_signature(0, witness_prog, 600_000_000)
    ).to be true
    expect(tx.in[0].script_sig).to eq(Bitcoin::Script.pack_pushdata(witness_prog))
  end

  it 'should allow txin.prev_out as tx or hash' do
    prev_tx = block.tx[0]
    tx1 = build_tx do |t|
      t.input { |i| i.prev_out prev_tx, 0 }
    end
    tx2 = build_tx do |t|
      t.input { |i| i.prev_out prev_tx.hash, 0, prev_tx.out[0].pk_script }
    end
    expect(tx1.in[0]).to eq(tx2.in[0])
  end

  it 'should provide tx#output shortcut' do
    tx1 = build_tx { |t| t.output(123, keys[1].addr) }
    expect(tx1).to eq(
      build_tx do |t|
        t.output do |o|
          o.value 123
          o.to keys[1].addr
        end
      end
    )

    tx2 = build_tx { |t| t.output(123, keys[1].pub, :pubkey) }
    expect(tx2).to eq(
      build_tx do |t|
        t.output do |o|
          o.value 123
          o.to keys[1].pub, :pubkey
        end
      end
    )
  end

  it 'should provide txout#to shortcut' do
    tx1 = build_tx do |t|
      t.output do |o|
        o.value 123
        o.to keys[1].addr
      end
    end
    tx2 = build_tx do |t|
      t.output do |o|
        o.value 123
        o.script { |s| s.recipient keys[1].addr }
      end
    end
    expect(tx1.out[0]).to eq(tx2.out[0])
  end

  it 'should build unsigned transactions and add the signature hash' do
    tx = build_tx do |t|
      t.input do |i|
        i.prev_out block.tx[0]
        i.prev_out_index 0
        # no signature key
      end
      t.output do |o|
        o.value 123
        o.script { |s| s.recipient keys[1].addr }
      end
    end

    expect(tx).to be_a(Bitcoin::P::Tx)
    expect(tx.in[0].sig_hash).not_to be_nil
  end

  it 'should build unsigned multisig transactions and add the signature hash' do
    tx1 = build_tx do |t|
      t.input do |i|
        i.prev_out(block.tx[0], 0)
        i.signature_key(keys[0])
      end
      t.output do |o|
        o.value 123
        o.to [2, *keys[0..2].map(&:pub)], :multisig
      end
    end

    tx2 = build_tx do |t|
      t.input do |i|
        i.prev_out tx1, 0
        i.signature_key keys[0]
      end
      t.output do |o|
        o.value 123
        o.to keys[0].addr
      end
    end

    expect(tx2).to be_a(Bitcoin::P::Tx)
    expect(tx2.in[0].sig_hash).not_to be_nil
  end

  it 'should build unsigned p2sh multisig transactions and add the signature hash' do
    tx1 = build_tx do |t|
      t.input do |i|
        i.prev_out(block.tx[0], 0)
        i.signature_key(keys[0])
      end
      t.output do |o|
        o.value 123
        o.to [2, *keys[0..2].map(&:pub)], :p2sh_multisig
      end
    end

    tx2 = build_tx do |t|
      t.input do |i|
        i.prev_out tx1, 0
        i.signature_key keys[0]
        i.redeem_script tx1.out[0].redeem_script
      end
      t.output do |o|
        o.value 123
        o.to keys[0].addr
      end
    end

    expect(tx2).to be_a(Bitcoin::P::Tx)
    expect(tx2.in[0].sig_hash).not_to be_nil
  end

  it 'should add change output' do
    change_address = Bitcoin::Key.generate.addr
    input_value = block.tx[0].out.map(&:value).inject(:+)

    tx = build_tx(input_value: input_value, change_address: change_address) do |t|
      t.input do |i|
        i.prev_out block.tx[0]
        i.prev_out_index 0
        i.signature_key keys[0]
      end
      t.output do |o|
        o.value 12_345
        o.script { |s| s.recipient keys[1].addr }
      end
    end

    expect(tx.out.count).to be(2)
    expect(tx.out.last.value).to eq(50e8 - 12_345)
    expect(
      Bitcoin::Script.new(tx.out.last.pk_script).get_address
    ).to eq(change_address)
  end

  it 'should add change output and leave fee' do
    change_address = Bitcoin::Key.generate.addr
    input_value = block.tx[0].out.map(&:value).inject(:+)

    tx = build_tx(input_value: input_value,
                  change_address: change_address, leave_fee: true) do |t|
      t.input do |i|
        i.prev_out block.tx[0]
        i.prev_out_index 0
        i.signature_key keys[0]
      end
      t.output do |o|
        o.value 12_345
        o.script { |s| s.recipient keys[1].addr }
      end
    end
    expect(tx.out.count).to eq(2)
    expect(tx.out.last.value)
      .to eq(50e8 - 12_345 - Bitcoin.network[:min_tx_fee])
    expect(
      Bitcoin::Script.new(tx.out.last.pk_script).get_address
    ).to eq(change_address)

    input_value = block.tx[0].out.map(&:value).inject(:+)
    tx = build_tx(input_value: input_value,
                  change_address: change_address, leave_fee: true) do |t|
      t.input do |i|
        i.prev_out block.tx[0]
        i.prev_out_index 0
        i.signature_key keys[0]
      end
      49.times do
        t.output do |o|
          o.value 1e8
          o.script { |s| s.recipient keys[1].addr }
        end
      end
      t.output do |o|
        o.value(1e8 - 10_000)
        o.script { |s| s.recipient keys[1].addr }
      end
    end

    expect(tx.out.size).to eq(50)
    expect(tx.out.map(&:value).inject(:+)).to eq(50e8 - 10_000)
  end

  it 'randomize_outputs should not modify output values or fees' do
    change_address = Bitcoin::Key.generate.addr
    input_value = block.tx[0].out.map(&:value).inject(:+)
    tx = build_tx(input_value: input_value,
                  change_address: change_address, leave_fee: true) do |t|
      t.input do |i|
        i.prev_out block.tx[0]
        i.prev_out_index 0
        i.signature_key keys[0]
      end
      t.output do |o|
        o.value 12_345
        o.script { |s| s.recipient keys[1].addr }
      end
      t.randomize_outputs
    end

    expect(tx.out.count).to eq(2)
    expect(tx.out.last.value).to eq(50e8 - 12_345 - Bitcoin.network[:min_tx_fee])
    expect(
      Bitcoin::Script.new(tx.out.last.pk_script).get_address
    ).to eq(change_address)

    input_value = block.tx[0].out.map(&:value).inject(:+)
    tx = build_tx(input_value: input_value,
                  change_address: change_address, leave_fee: true) do |t|
      t.input do |i|
        i.prev_out block.tx[0]
        i.prev_out_index 0
        i.signature_key keys[0]
      end
      49.times do
        t.output do |o|
          o.value 1e8
          o.script { |s| s.recipient keys[1].addr }
        end
      end
      t.output do |o|
        o.value(1e8 - 10_000)
        o.script { |s| s.recipient keys[1].addr }
      end
      t.randomize_outputs
    end

    expect(tx.out.size).to eq(50)
    expect(tx.out.map(&:value).inject(:+)).to eq(50e8 - 10_000)
  end

  it 'should build op_return output' do
    builder = Bitcoin::Builder::TxOutBuilder.new
    builder.to 'deadbeef', :op_return

    expect(builder.txout.parsed_script.to_string).to eq('OP_RETURN deadbeef')
  end

  it 'should build op_return script' do
    result = script do |s|
      s.type :op_return
      s.recipient 'deadbeef'
    end

    expect(Bitcoin::Script.new(result).to_string).to eq('OP_RETURN deadbeef')
  end

  it 'should build address script' do
    key = Bitcoin::Key.generate
    result = script do |s|
      s.type :address
      s.recipient key.addr
    end

    expect(Bitcoin::Script.new(result).to_string)
      .to eq("OP_DUP OP_HASH160 #{Bitcoin.hash160_from_address(key.addr)} " \
             'OP_EQUALVERIFY OP_CHECKSIG')
  end

  it 'should build pubkey script' do
    key = Bitcoin::Key.generate
    result = script do |s|
      s.type :pubkey
      s.recipient key.pub
    end

    expect(Bitcoin::Script.new(result).to_string)
      .to eq("#{key.pub} OP_CHECKSIG")
  end

  it 'should build multisig script' do
    keys = Array.new(3) { Bitcoin::Key.generate }
    result = script do |s|
      s.type :multisig
      s.recipient 1, keys[0].pub, keys[1].pub
    end

    expect(Bitcoin::Script.new(result).to_string)
      .to eq("1 #{keys[0].pub} #{keys[1].pub} 2 OP_CHECKMULTISIG")
  end

  it 'should build and spend multisig output' do
    tx1 = build_tx do |t|
      t.input do |i|
        i.prev_out(block.tx[0], 0)
        i.signature_key(keys[0])
      end
      t.output do |o|
        o.value 123
        o.to [2, *keys[0..2].map(&:pub)], :multisig
      end
    end

    expect(
      Bitcoin::Script.new(tx1.out[0].pk_script).to_string
    ).to eq("2 #{keys[0..2].map(&:pub).join(' ')} 3 OP_CHECKMULTISIG")

    tx2 = build_tx do |t|
      t.input do |i|
        i.prev_out tx1, 0
        i.signature_key keys[0..1]
      end
      t.output do |o|
        o.value 123
        o.to keys[0].addr
      end
    end

    expect(tx2.verify_input_signature(0, tx1)).to be true
  end

  it 'should build and spend p2sh multisig output' do
    tx1 = build_tx do |t|
      t.input do |i|
        i.prev_out(block.tx[0], 0)
        i.signature_key(keys[0])
      end
      t.output do |o|
        o.value 123
        o.to [2, *keys[0..2].map(&:pub)], :p2sh_multisig
      end
    end

    expect(Bitcoin::Script.new(tx1.out[0].pk_script).to_string)
      .to eq("OP_HASH160 #{Bitcoin.hash160(tx1.out[0].redeem_script.hth)} OP_EQUAL")

    tx2 = build_tx do |t|
      t.input do |i|
        i.prev_out tx1, 0
        # provide 2 required keys for signing
        i.signature_key keys[0..1]
        # provide the redeem script from the previous output
        i.redeem_script tx1.out[0].redeem_script
      end

      t.output do |o|
        o.value 123
        o.to keys[0].addr
      end
    end

    script = Bitcoin::Script.new(tx2.in[0].script_sig, tx1.out[0].pk_script)
    # check script execution is valid
    expect(script.run { true }).to be true
    # check signatures are valid
    expect(tx2.verify_input_signature(0, tx1)).to be true
  end

  it 'should build and sign bcash transaction' do
    tx = build_tx do |t|
      t.input do |i|
        prev_tx = block.tx[0]
        utxo = prev_tx.out[0]
        i.prev_out prev_tx.hash, 0, utxo.script, utxo.amount, 0
        i.signature_key keys[0]
      end

      t.output do |o|
        o.value 4_999_900_000

        o.script do |s|
          s.type :address
          s.recipient keys[1].addr
        end
      end
    end

    expect(tx.in[0].prev_out.reverse_hth).to eq(block.tx[0].hash)
    expect(tx.in[0].prev_out_index).to eq(0)
    expect(
      Bitcoin::Script.new(tx.in[0].script_sig).chunks[1].unpack('H*')[0]
    ).to eq(keys[0].pub)
    expect(tx.out[0].value).to eq(4_999_900_000)

    script = Bitcoin::Script.new(tx.out[0].pk_script)
    expect(script.type).to eq(:hash160)
    expect(script.get_address).to eq(keys[1].addr)
    expect(
      tx.verify_input_signature(0, block.tx[0], Time.now.to_i, fork_id: 0)
    ).to be true
    expect(Bitcoin::Script.new(tx.out[0].pk_script).to_string)
      .to eq("OP_DUP OP_HASH160 #{keys[1].hash160} OP_EQUALVERIFY OP_CHECKSIG")
  end
end
