# frozen_string_literal: true

require 'spec_helper'

describe Bitcoin::Script do
  # Re-open script class
  module Bitcoin
    # Add accessors for private member variables.
    class Script
      attr_writer :stack
      attr_accessor :stack_alt
    end
  end

  let(:script) { Bitcoin::Script.new('') }

  # Invoke the given operation on the initial stack provided.
  #
  # @param operation [String,Symbol] name of the operation to be performed.
  # @param stack [Array<String>] stack state prior to operation.
  # @return [Array<String>] stack state after the operation.
  def op(operation, stack)
    script.stack = stack
    script.send("op_#{operation}")
    script.stack
  end

  # Run a script and check if result matches the hash provided.
  #
  # @param string [String] text script to be run.
  # @param hash [String] data expected to have been signed by key.
  # @return [Boolean] true if script ran and verified successfully, false
  #   otherwise.
  def run_script(string, hash)
    script = Bitcoin::Script.from_string(string)
    script.run do |pk, sig, _|
      begin
        k = Bitcoin::Key.new(nil, pk.unpack('H*')[0])
        k && k.verify(hash, sig)
      rescue StandardError
        false
      end
    end == true
  end

  it 'should do OP_NOP' do
    expect(op(:nop, ['foobar'])).to eq(['foobar'])
  end

  it 'should do OP_DUP' do
    expect(op(:dup, ['foobar'])).to eq(%w[foobar foobar])
  end

  it 'should do OP_SHA256' do
    expect(op(:sha256, ['foobar']))
      .to eq(
        [['c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2'].pack('H*')]
      )
  end

  it 'should do OP_SHA1' do
    expect(op(:sha1, ['foobar']))
      .to eq([['8843d7f92416211de9ebb963ff4ce28125932878'].pack('H*')])
  end

  it 'should do OP_HASH160' do
    expect(op(:hash160, ['foobar']))
      .to eq([['f6c97547d73156abb300ae059905c4acaadd09dd'].pack('H*')])
  end

  it 'should do OP_RIPEMD160' do
    expect(op(:ripemd160, ['foobar']))
      .to eq([['a06e327ea7388c18e4740e350ed4e60f2e04fc41'].pack('H*')])
  end

  it 'should do OP_HASH256' do
    expect(op(:hash256, ['foobar']))
      .to eq(
        [['3f2c7ccae98af81e44c0ec419659f50d8b7d48c681e5d57fc747d0461e42dda1'].pack('H*')]
      )
  end

  it 'should do OP_TOALTSTACK' do
    expect(op(:toaltstack, ['foobar'])).to be_empty
    expect(script.stack_alt).to eq(['foobar'])
  end

  it 'should do OP_FROMALTSTACK' do
    script.instance_eval { @stack = [] }
    script.instance_eval { @stack_alt = ['foo'] }
    script.op_fromaltstack
    expect(script.stack).to eq(['foo'])
    expect(script.stack_alt).to be_empty
  end

  it 'should do OP_TUCK' do
    expect(op(:tuck, %w[foobar foo bar])).to eq(%w[foobar bar foo bar])
  end

  it 'should do OP_SWAP' do
    expect(op(:swap, %w[foo bar])).to eq(%w[bar foo])
  end

  it 'should do OP_BOOLAND' do
    expect(op(:booland, [0, 0])).to eq([0])
    expect(op(:booland, [0, 1])).to eq([0])
    expect(op(:booland, [1, 0])).to eq([0])
    expect(op(:booland, [1, 1])).to eq([1])
  end

  it 'should do OP_ADD' do
    expect(op(:add, [0, 1])).to eq([1])
    expect(op(:add, [3, 4])).to eq([7])
    expect(op(:add, [5, -4])).to eq([1])
  end

  it 'should do OP_SUB' do
    expect(op(:sub, [3, 2])).to eq([1])
    expect(op(:sub, [9, 1])).to eq([8])
    expect(op(:sub, [1, 3])).to eq([-2])
  end

  it 'should do OP_GREATERTHANOREQUAL' do
    expect(op(:greaterthanorequal, [2, 1])).to eq([1])
    expect(op(:greaterthanorequal, [2, 2])).to eq([1])
    expect(op(:greaterthanorequal, [1, 2])).to eq([0])
  end

  it 'should do OP_DROP' do
    expect(op(:drop, ['foo'])).to be_empty
  end

  it 'should do OP_EQUAL' do
    expect(op(:equal, [1, 2])).to eq([0])
    expect(op(:equal, [1, 1])).to eq([1])
  end

  it 'should do OP_VERIFY' do
    expect(op(:verify, [1])).to be_empty
    expect(op(:verify, [0])).to eq([0])
  end

  it 'should do OP_EQUALVERIFY' do
    expect(op(:equalverify, [1, 2])).to eq([0])
    expect(script).to be_invalid
    expect(op(:equalverify, [1, 1])).to be_empty
    expect(script).not_to be_invalid
  end

  it 'should do OP_0' do
    expect(op('0', ['foo'])).to eq(['foo', ''])
  end

  it 'should do OP_1' do
    expect(op('1', ['foo'])).to eq(['foo', 1])
  end

  it 'should do OP_MIN' do
    [
      [[4, 5], 4],
      [[5, 4], 4],
      [[4, 4], 4],
      [["\x04", "\x05"], 4],
      [[1, 0], 0],
      [[0, 1], 0],
      [[-1, 0], -1],
      [[0, -2_147_483_647], -2_147_483_647]
    ].each do |stack, expected|
      expect(op(:min, stack)).to eq([expected])
    end
  end

  it 'should do OP_MAX' do
    [
      [[4, 5], 5],
      [[5, 4], 5],
      [[4, 4], 4],
      [["\x04", "\x05"], 5],
      [[2_147_483_647, 0], 2_147_483_647],
      [[0, 100], 100],
      [[-100, 0], 0],
      [[0, -2_147_483_647], 0]
    ].each do |stack, expected|
      expect(op(:max, stack)).to eq([expected])
    end
  end

  it 'should do op_2over' do
    expect(op('2over', [1, 2, 3, 4])).to eq([1, 2, 3, 4, 1, 2])
  end

  it 'should do op_2swap' do
    expect(op('2swap', [1, 2, 3, 4])).to eq([3, 4, 1, 2])
  end

  it 'should do op_ifdup' do
    expect(op(:ifdup, [1])).to eq([1, 1])
    expect(op(:ifdup, ['a'])).to eq(%w[a a])
    expect(op(:ifdup, [0])).to eq([0])
  end

  it 'should do op_1negate' do
    expect(op('1negate', [])).to eq([-1])
  end

  it 'should do op_depth' do
    expect(op(:depth, [])).to eq([0])
    expect(op(:depth, [1, 2, 3])).to eq([1, 2, 3, 3])
  end

  it 'should do op_boolor' do
    [
      [[1, 1], 1],
      [[1, 0], 1],
      [[0, 1], 1],
      [[0, 0], 0],
      [[16, 17], 1],
      [[-1, 0], 1]
      # [[1     ], :invalid],
    ].each do |stack, expected|
      expect(op(:boolor, stack)).to eq([expected])
    end
  end

  it 'should do op_lessthan' do
    [
      [[11, 10], 0],
      [[4, 4], 0],
      [[10, 11], 1],
      [[-11, 11], 1],
      [[-11, -10], 1],
      [[-1, 0], 1]
    ].each do |stack, expected|
      expect(op(:lessthan, stack)).to eq([expected])
    end
  end

  it 'should do op_lessthanorequal' do
    [
      [[11, 10], 0],
      [[4, 4], 1],
      [[10, 11], 1],
      [[-11, 11], 1],
      [[-11, -10], 1],
      [[-1, 0], 1]
    ].each do |stack, expected|
      expect(op(:lessthanorequal, stack)).to eq([expected])
    end
  end

  it 'should do op_greaterthan' do
    [
      [[11, 10], 1],
      [[4, 4], 0],
      [[10, 11], 0],
      [[-11, 11], 0],
      [[-11, -10], 0],
      [[-1, 0], 0],
      [[1, 0], 1]
    ].each do |stack, expected|
      expect(op(:greaterthan, stack)).to eq([expected])
    end
  end

  it 'should do op_greaterthanorequal' do
    [
      [[11, 10], 1],
      [[4, 4], 1],
      [[10, 11], 0],
      [[-11, 11], 0],
      [[-11, -10], 0],
      [[-1, 0], 0],
      [[1, 0], 1],
      [[0, 0], 1]
    ].each do |stack, expected|
      expect(op(:greaterthanorequal, stack)).to eq([expected])
    end
  end

  it 'should do op_not' do
    expect(op(:not, [0])).to eq([1])
    expect(op(:not, [1])).to eq([0])
  end

  it 'should do op_0notequal' do
    [
      [[0], 0],
      [[1], 1],
      [[111], 1],
      [[-111], 1]
    ].each do |stack, expected|
      expect(op('0notequal', stack)).to eq([expected])
    end
  end

  it 'should do op_abs' do
    [
      [[0], 0],
      [[16], 16],
      [[-16], 16],
      [[-1], 1]
    ].each do |stack, expected|
      expect(op(:abs, stack)).to eq([expected])
    end
  end

  it 'should do op_2div' do
    expect(op('2div', [2])).to eq([1])
    expect(op('2div', [10])).to eq([5])
    expect(op('2div', [-10])).to eq([-5])
  end

  it 'should do op_2mul' do
    expect(op('2mul', [2])).to eq([4])
    expect(op('2mul', [10])).to eq([20])
    expect(op('2mul', [-10])).to eq([-20])
  end

  it 'should do op_1add' do
    expect(op('1add', [2])).to eq([3])
    expect(op('1add', [10])).to eq([11])
    expect(op('1add', [-10])).to eq([-9])
  end

  it 'should do op_1sub' do
    expect(op('1sub', [2])).to eq([1])
    expect(op('1sub', [10])).to eq([9])
    expect(op('1sub', [-10])).to eq([-11])
  end

  it 'should do op_negate' do
    expect(op('negate', [-2])).to eq([2])
    expect(op('negate', [2])).to eq([-2])
    expect(op('negate', [0])).to eq([0])
  end

  it 'should do op_within' do
    [
      [[0, 0, 1], 1],
      [[1, 0, 1], 0],
      [[0, -2_147_483_647, 2_147_483_647], 1],
      [[-1, -100, 100], 1],
      [[11, -100, 100], 1],
      [[-2_147_483_647, -100, 100], 0],
      [[2_147_483_647, -100, 100], 0],
      [[-1, -1, 0], 1]
    ].each do |stack, expected|
      expect(op(:within, stack)).to eq([expected])
    end
  end

  it 'should do op_numequal' do
    [
      [[0, 0], 1],
      [[0, 1], 0]
    ].each do |stack, expected|
      expect(op(:numequal, stack)).to eq([expected])
    end
  end

  it 'should do op_numequalverify' do
    [
      [[0, 0], []],
      [[0, 1], [0]]
    ].each do |stack, expected|
      expect(op(:numequalverify, stack)).to eq(expected)
    end
  end

  it 'should do op_numnotequal' do
    [
      [[0, 0], 0],
      [[0, 1], 1]
    ].each do |stack, expected|
      expect(op(:numnotequal, stack)).to eq([expected])
    end
  end

  it 'should do op_over' do
    [
      [[1, 0], [1, 0, 1]],
      [[-1, 1], [-1, 1, -1]],
      [[1], [1]]
    ].each do |stack, expected|
      expect(op(:over, stack)).to eq(expected)
    end
  end

  it 'should do op_pick' do
    [
      [[1, 0, 0, 0, 3], [1, 0, 0, 0, 1]],
      [[1, 0], [1, 1]]
    ].each do |stack, expected|
      expect(op(:pick, stack)).to eq(expected)
      expect(script).not_to be_invalid
    end

    [
      [[0], [0]],
      [[-1], [-1]]
    ].each do |stack, expected|
      expect(op(:pick, stack)).to eq(expected)
      expect(script).to be_invalid
    end
  end

  it 'should do op_roll' do
    [
      [[1, 0, 0, 0, 3], [0, 0, 0, 1]],
      [[1, 0], [1]]
    ].each do |stack, expected|
      expect(op(:roll, stack)).to eq(expected)
      expect(script).not_to be_invalid
    end

    [
      [[0], [0]],
      [[-1], [-1]]
    ].each do |stack, expected|
      expect(op(:roll, stack)).to eq(expected)
      expect(script).to be_invalid
    end
  end

  it 'should do op_2rot' do
    expect(op('2rot', [-1, 0, 1, 2, 3, 4, 5, 6]))
      .to eq([-1, 0, 3, 4, 5, 6, 1, 2])
    expect(script).not_to be_invalid

    expect(op('2rot', [2, 3, 4, 5, 6])).to eq([2, 3, 4, 5, 6])
    expect(script).to be_invalid
  end

  it 'should do op_rot' do
    expect(op(:rot, [22, 21, 20])).to eq([21, 20, 22])
    expect(op(:rot, [21, 20])).to eq([21, 20])
  end

  it 'should do op_2drop' do
    expect(op('2drop', [1, 2, 3])).to eq([1])
    expect(op('2drop', [2, 3])).to be_empty
  end

  it 'should do op_2dup' do
    expect(op('2dup', [2, 3])).to eq([2, 3, 2, 3])
    expect(op('2dup', [3])).to eq([3])
  end

  it 'should do op_3dup' do
    expect(op('3dup', [1, 2, 3])).to eq([1, 2, 3, 1, 2, 3])
    expect(op('3dup', [2, 3])).to eq([2, 3])
    expect(op('3dup', [3])).to eq([3])
  end

  it 'should do op_nip' do
    expect(op(:nip, [1, 2])).to eq([2])
    expect(op(:nip, [1, 2, 3])).to eq([1, 3])
  end

  it 'should do op_size' do
    [
      [[0], [0, 0]],
      [[1], [1, 1]],
      [[127], [127, 1]],
      [[128], [128, 2]],
      [[32_767], [32_767, 2]],
      [[32_768], [32_768, 3]],
      [[8_388_607], [8_388_607, 3]],
      [[8_388_608], [8_388_608, 4]],
      [[2_147_483_647], [2_147_483_647, 4]],
      [[2_147_483_648], [2_147_483_648, 5]],
      [[-1], [-1, 1]],
      [[-127], [-127, 1]],
      [[-128], [-128, 2]],
      [[-32_767], [-32_767, 2]],
      [[-32_768], [-32_768, 3]],
      [[-8_388_607], [-8_388_607, 3]],
      [[-8_388_608], [-8_388_608, 4]],
      [[-2_147_483_647], [-2_147_483_647, 4]],
      [[-2_147_483_648], [-2_147_483_648, 5]],
      [['abcdefghijklmnopqrstuvwxyz'], ['abcdefghijklmnopqrstuvwxyz', 26]]
    ].each do |stack, expected|
      expect(op(:size, stack)).to eq(expected)
    end
  end

  it 'should do if/notif/else/end' do
    [
      '1 1 OP_IF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ENDIF',
      '1 0 OP_IF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ENDIF',
      '1 1 OP_IF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ELSE OP_IF 0 OP_ELSE 1 OP_ENDIF OP_ENDIF',
      '0 0 OP_IF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ELSE OP_IF 0 OP_ELSE 1 OP_ENDIF OP_ENDIF',
      '1 1 OP_NOTIF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ENDIF',
      '1 0 OP_NOTIF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ENDIF',
      '1 0 OP_NOTIF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ELSE OP_IF 0 OP_ELSE 1 OP_ENDIF OP_ENDIF',
      '0 1 OP_NOTIF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ELSE OP_IF 0 OP_ELSE 1 OP_ENDIF OP_ENDIF',
      '0 OP_IF OP_RETURN OP_ENDIF 1',
      '1 OP_IF 1 OP_ENDIF',
      '0 OP_IF 50 OP_ENDIF 1',
      '0 OP_IF OP_VER OP_ELSE 1 OP_ENDIF',
      '0 OP_IF 50 40 OP_ELSE 1 OP_ENDIF',
      '1 OP_DUP OP_IF OP_ENDIF',
      '1 OP_IF 1 OP_ENDIF',
      '1 OP_DUP OP_IF OP_ELSE OP_ENDIF',
      '1 OP_IF 1 OP_ELSE OP_ENDIF',
      '0 OP_IF OP_ELSE 1 OP_ENDIF',
      'beef OP_IF 1 OP_ELSE 0 OP_ENDIF',
      '0 OP_NOTIF 1 OP_ELSE 0 OP_ENDIF',
      'beef OP_NOTIF 0 OP_ELSE 1 OP_ENDIF'
    ].each do |script|
      expect(Bitcoin::Script.from_string(script).run).to be true
    end
  end

  it 'should do OP_CHECKSIG' do
    script.stack = %w[bar foo]
    verify_callback = proc do |pubkey, signature, type|
      expect(pubkey).to eq('foo')
      expect(signature).to eq('ba')
      expect(type).to eq('r'.ord)
      true
    end
    expect(script.op_checksig(verify_callback)).to eq([1])

    script.stack = %w[bar foo]
    verify_callback = proc { true }
    expect(script.op_checksig(verify_callback)).to eq([1])

    script.stack = %w[bar foo]
    verify_callback = proc { false }
    expect(script.op_checksig(verify_callback)).to eq([0])

    script.stack = ['foo']
    verify_callback = proc { false }
    expect(script.op_checksig(verify_callback)).to be_nil

    pubkey = [
      '04324c6ebdcf079db6c9209a6b715b955622561262cde13a8a1df8ae0ef030eaa1552' \
      'e31f8be90c385e27883a9d82780283d19507d7fa2e1e71a1d11bc3a52caf3'
    ].pack('H*')
    signature = [
      '304402202c2fb840b527326f9bbc7ce68c6c196a368a38864b5a47681352c4b2f416f' \
      '7ed02205c4801cfa8aed205f26c7122ab5a5934fcf7a2f038fd130cdd8bcc56bdde0a00'
    ].pack('H*')
    hash_type = [1].pack('C')
    signature_data = [
      '20245059adb84acaf1aa942b5d8a586da7ba76f17ecb5de4e7543e1ce1b94bc3'
    ].pack('H*')

    script.stack = [signature + hash_type, pubkey]
    verify_callback = proc do |pub, sig, hash_t|
      expect(pub).to eq(pubkey)
      expect(sig).to eq(signature)
      expect(hash_t).to eq(1)

      hash = signature_data
      Bitcoin.verify_signature(hash, sig, pub.unpack('H*')[0])
    end
    expect(script.op_checksig(verify_callback)).to eq([1])

    script.stack = [signature + hash_type, 1]
    verify_callback = proc do |pub, _, _|
      pub.is_a?(String)
    end
    expect(script.op_checksig(verify_callback)).to eq([1])

    script.stack = [signature + hash_type, pubkey]
    verify_callback = proc do |pub, sig, _|
      hash = 'foo' + signature_data
      Bitcoin.verify_signature(hash, sig, pub.unpack('H*')[0])
    end
    expect(script.op_checksig(verify_callback)).to eq([0])

    script.stack = [signature + hash_type, pubkey]
    verify_callback = proc do |pub, _, _|
      hash = signature_data
      Bitcoin.verify_signature(hash, 'foo', pub.unpack('H*')[0])
    end
    expect(script.op_checksig(verify_callback)).to eq([0])

    script.stack = [signature + hash_type, pubkey]
    verify_callback = proc do |_, sig, _|
      hash = signature_data
      Bitcoin.verify_signature(hash, sig, 'foo')
    end
    expect(script.op_checksig(verify_callback)).to eq([0])

    # Bitcoin::Key API
    key = Bitcoin::Key.new
    key.generate
    signature = (key.sign('foobar') + "\x01").unpack('H*')[0]
    script = Bitcoin::Script.from_string("#{signature} #{key.pub} OP_CHECKSIG")
    result = script.run do |pk, sig, _|
      k = Bitcoin::Key.new nil, pk.unpack('H*')[0]
      k.verify('foobar', sig)
    end

    expect(result).to be true
    expect(script.stack).to be_empty
  end

  it 'should do OP_CHECKMULTISIG' do
    k1 = Bitcoin::Key.new
    k2 = Bitcoin::Key.new
    k3 = Bitcoin::Key.new
    k1.generate
    k2.generate
    k3.generate
    sig1 = (k1.sign('foobar') + "\x01").unpack('H*')[0]
    sig2 = (k2.sign('foobar') + "\x01").unpack('H*')[0]
    sig3 = (k3.sign('foobar') + "\x01").unpack('H*')[0]

    script = "0 #{sig1} 1 #{k1.pub} 1 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be true

    script = "0 #{sig1} #{sig2} 2 #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be true

    script = "0 #{sig2} #{sig1} 2 #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false

    script = "0 #{sig1} #{sig2} 2 #{k2.pub} #{k1.pub} 2 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false

    script = "0 #{sig1} #{sig2} 2 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be true

    script = "0 #{sig2} #{sig3} 2 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be true

    script = "0 #{sig1} #{sig2} #{sig3} 3 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be true

    # without OP_NOP
    script = "#{sig1} #{sig2} #{sig3} 3 #{k1.pub} #{k2.pub} #{k3.pub} 3 " \
             'OP_CHECKMULTISIG'
    expect(run_script(script, 'foobar')).to be true

    script = "0 #{sig2} 1 #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be true

    script = "0 #{sig2} OP_TRUE #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be true

    script = "0 #{sig1} #{sig2} #{sig3} 3 #{k1.pub} #{k2.pub} #{k3.pub} 2 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false

    script = "0 #{sig1} #{sig2} #{sig3} 3 #{k2.pub} #{k3.pub} 2 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false

    script = "0 #{sig1} #{sig2} #{sig3} 3 2 #{k3.pub} 2 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false

    script = "0 #{sig1} #{sig2} #{sig3} 3 0 #{k3.pub} 2 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false

    script = "0 #{sig1} #{sig2} 2 3 #{k2.pub} #{k3.pub} 2 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false

    script = "0 #{sig1} #{sig2} 0 3 #{k2.pub} #{k3.pub} 2 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false

    script = "0 #{sig2} f0f0f0f0 2 #{k1.pub} #{k2.pub} 2 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false

    script = "0 afafafaf #{sig2} 2 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false

    script = "0 #{sig1} f0f0f0f0 #{sig3} 3 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false

    script = "0 #{sig1} f0f0f0f0 #{sig3} 3 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG OP_NOT"
    expect(run_script(script, 'foobar')).to be true

    script = '1 1 1 1 1 OP_CHECKMULTISIG OP_NOT'
    expect(run_script(script, 'foobar')).to be true

    # mainnet tx output: 514c46f0b61714092f15c8dfcb576c9f79b3f959989b98de3944b19d98832b58
    script = "0 #{sig1} 1 0 #{k1.pub} OP_SWAP OP_1ADD OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be true
    expect(Bitcoin::Script.from_string(script).get_addresses).to be_empty
    expect(Bitcoin::Script.from_string(script).is_multisig?).to be false
    script = "#{k1.pub} OP_SWAP OP_1ADD OP_CHECKMULTISIG"
    expect(Bitcoin::Script.from_string(script).get_addresses).to be_empty
    expect(Bitcoin::Script.from_string(script).is_multisig?).to be false

    script = "0 #{sig2} #{sig1} 2 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false
    script = "0 #{sig3} #{sig2} 2 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false
    script = "0 #{sig1} #{sig3} #{sig2} 3 #{k1.pub} #{k2.pub} #{k3.pub} 3 OP_CHECKMULTISIG"
    expect(run_script(script, 'foobar')).to be false
  end

  it 'should do P2SH' do
    k1 = Bitcoin::Key.new
    k1.generate
    sig = (k1.sign('foobar') + "\x01").unpack('H*')[0]
    inner_script = Bitcoin::Script.from_string("#{k1.pub} OP_CHECKSIG").raw.unpack('H*')[0]
    script_hash = Bitcoin.hash160(inner_script)
    script = Bitcoin::Script.from_string(
      "#{sig} #{inner_script} OP_HASH160 #{script_hash} OP_EQUAL"
    )
    expect(script.is_p2sh?).to be true
    expect(run_script(script.to_string, 'foobar')).to be true
    expect(run_script(script.to_string, 'barbaz')).to be false

    script = Bitcoin::Script.from_string(
      "0 #{sig} #{inner_script} OP_HASH160 #{script_hash} OP_EQUAL"
    )
    expect(script.is_p2sh?).to be true
    expect(run_script(script.to_string, 'foobar')).to be true

    script = Bitcoin::Script.from_string("OP_HASH160 #{script_hash} OP_EQUAL")
    expect(script.is_p2sh?).to be true
    expect(run_script(script.to_string, 'foobar')).to be false

    address = '3CkxTG25waxsmd13FFgRChPuGYba3ar36B'
    script = Bitcoin::Script.new(Bitcoin::Script.to_address_script(address))
    expect(script.type).to eq(:p2sh)

    inner_script = Bitcoin::Script.from_string('0 OP_NOT').raw.unpack('H*')[0]
    script_hash = Bitcoin.hash160(inner_script)
    script = Bitcoin::Script.from_string("#{inner_script} OP_HASH160 #{script_hash} OP_EQUAL")
    expect(script.is_p2sh?).to be true
    expect(run_script(script.to_string, 'foobar')).to be true
  end

  it 'should skip OP_EVAL' do
    expect(Bitcoin::Script.from_string('1 OP_EVAL').to_string).to eq('1 OP_NOP1')
    expect(Bitcoin::Script.from_string('1 OP_EVAL').run).to be true
    expect(Bitcoin::Script.from_string('0 OP_EVAL').run).to be false
  end

  it 'should do testnet3 scripts' do
    [
      'OP_1NEGATE OP_1NEGATE OP_ADD 82 OP_EQUAL',
      '6f 1 OP_ADD 12 OP_SUB 64 OP_EQUAL',
      '76:1:07 7 OP_EQUAL',
      'OP_1NEGATE e4 64 OP_WITHIN',
      '0 ffffffff ffffff7f OP_WITHIN',
      '6162636465666768696a6b6c6d6e6f707172737475767778797a OP_SIZE 1a OP_EQUAL',
      '0 OP_IFDUP OP_DEPTH 1 OP_EQUALVERIFY 0 OP_EQUAL',
      '1 OP_NOP1 OP_CHECKHASHVERIFY OP_NOP3 OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 ' \
      'OP_NOP8 OP_NOP9 OP_NOP10 1 OP_EQUAL',
      '1 OP_NOP1 OP_NOP2 OP_NOP3 OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 ' \
      'OP_NOP9 OP_NOP10 1 OP_EQUAL',
      '0 ffffffff ffffff7f OP_WITHIN',
      '0:1:16 0:1:15 0:1:14 OP_ROT OP_ROT 0:1:15 OP_EQUAL',
      'ffffff7f OP_NEGATE OP_DUP OP_ADD feffffff80 OP_EQUAL',
      '90 OP_ABS 90 OP_NEGATE OP_EQUAL',
      '0 OP_DROP OP_DEPTH 0 OP_EQUAL',
      '1 0 OP_NOTIF OP_IF 1 OP_ELSE 0 OP_ENDIF OP_ELSE OP_IF 0 OP_ELSE 1 OP_ENDIF OP_ENDIF',
      '6f OP_1SUB 6e OP_EQUAL',
      '13 14 OP_2DUP OP_ROT OP_EQUALVERIFY OP_EQUAL',
      '10 0 11 OP_TOALTSTACK OP_DROP OP_FROMALTSTACK OP_ADD 0:1:15 OP_EQUAL',
      'ffffff7f OP_DUP OP_ADD feffffff00 OP_EQUAL',
      '77:1:08 8 OP_EQUAL',
      '1 OP_NOT 0 OP_EQUAL',
      '0 OP_DROP OP_DEPTH 0 OP_EQUAL',
      '6f 1 OP_ADD 12 OP_SUB 64 OP_EQUAL',
      '0:1:0b 11 OP_EQUAL',
      '13 14 OP_2DUP OP_ROT OP_EQUALVERIFY OP_EQUAL',
      'ffffff7f OP_DUP OP_ADD feffffff00 OP_EQUAL',
      '0 OP_DROP OP_DEPTH 0 OP_EQUAL',
      '0 ffffffff OP_MIN ffffffff OP_NUMEQUAL',
      '90 OP_ABS 90 OP_NEGATE OP_EQUAL',
      'OP_1NEGATE e803 OP_ADD e703 OP_EQUAL',
      '0:1:16 0:1:15 0:1:14 OP_ROT OP_ROT OP_ROT 0:1:14 OP_EQUAL',
      '13 14 OP_2DUP OP_ROT OP_EQUALVERIFY OP_EQUAL',
      '8b 11 OP_LESSTHANOREQUAL',
      'ffffff7f ffffffff OP_ADD 0 OP_EQUAL',
      'ffffff7f OP_NEGATE OP_DUP OP_ADD feffffff80 OP_EQUAL',
      '8b 11 OP_GREATERTHANOREQUAL OP_NOT',
      '0 OP_0NOTEQUAL 0 OP_EQUAL',
      '2 82 OP_ADD 0 OP_EQUAL'
    ].each do |script|
      parsed_script = Bitcoin::Script.from_string(script)
      result = parsed_script.run
      expect(result).to be true
    end

    [
      'ffffff7f ffffff7f OP_ADD ffffff7f OP_ADD OP_TRUE'
    ].each do |script|
      parsed_script = Bitcoin::Script.from_string(script)
      result = parsed_script.run
      expect(result).to be false
    end
  end

  it 'should do OP_VER' do
    s = Bitcoin::Script.from_string('OP_VER')
    s.run
    expect(s).to be_invalid

    s = Bitcoin::Script.from_string('1 OP_IF OP_VER 1 OP_ELSE 0 OP_ENDIF')
    expect(s.run).to be false
    expect(s).to be_invalid

    s = Bitcoin::Script.from_string('1 OP_IF 1 OP_ELSE OP_VER 0 OP_ENDIF')
    expect(s.run).to be true
    expect(s).not_to be_invalid
  end

  it 'should not allow DISABLED_OPCODES' do
    Bitcoin::Script::DISABLED_OPCODES.each do |opcode|
      s = Bitcoin::Script.from_string(Bitcoin::Script::OPCODES[opcode] + ' 1')
      expect(s.run).to be false
      expect(s).to be_invalid

      s = Bitcoin::Script.from_string(
        "1 OP_IF #{Bitcoin::Script::OPCODES[opcode]} 1 OP_ELSE 1 OP_ENDIF"
      )
      expect(s.run).to be false
      expect(s).to be_invalid

      s = Bitcoin::Script.from_string(
        "1 OP_IF 1 OP_ELSE #{Bitcoin::Script::OPCODES[opcode]} 1 OP_ENDIF"
      )
      expect(s.run).to be false
      expect(s).to be_invalid
    end
  end

  it 'check before casting and mark bad cases invalid' do
    # tries to pop off an element from the empty stack here.
    s = Bitcoin::Script.from_string('OP_NOT')
    expect(s.run).to be false
    expect(s).to be_invalid
  end

  it 'should do OP_CHECKSIGVERIFY and OP_CHECKMULTISIGVERIFY' do
    tx1 = Bitcoin::P::Tx.new(
      '0100000001a3fe4396b575690095bfc088d864aa971c99f65e2d893b48e0b26b1b60a2' \
      '8754000000006a47304402201ddfc8e3f825add9f42c0ce76dc5709cf76871e7ee6c97' \
      'aae11d7db7f829b3f202201c3043515bfcf3d77845c8740ce4ccb4bda3f431da64f259' \
      '6ee0ea2dfb727a5c01210328a5915165382c9b119d10d313c5781d98a7de79225f3c58' \
      'e7fa115660ba90e0ffffffff0270f305000000000017a914ca164de1946bf0146ed1f3' \
      '2413df0efb0e1c730f87005d8806000000001976a91437c1d63690e00845663f3de661' \
      'fef981c08e8de588ac00000000'.htb
    )
    tx2 = Bitcoin::P::Tx.new(
      '0100000001a1c5263304aa47f8e4e8a8dbca33e525667f7f0d84390c5a92d49eccbe5b' \
      '970f00000000fde50152483045022100fbc7ccd87ad2384a4d8823d3cf36d839bb6acc' \
      'a3d80a9ed9c51c784b7bdf1e430220305fcb1660219fcc340935000aa92dd02684b763' \
      '177b8a3c1be094c919af323701473044022008f66d2e31175cdefbd7461afb5f9946e5' \
      'dcb8173d1a2d3ef837f1c810695d160220250354de77b4a919b87910aa203ecec54bd1' \
      '006d2dad2fcac06a54f39a9d39a101514d4f0176519c6375522103b124c48bbff7ebe1' \
      '6e7bd2b2f2b561aa53791da678a73d2777cc1ca4619ab6f72103ad6bb76e00d124f07a' \
      '22680e39debd4dc4bdb1aa4b893720dd05af3c50560fdd52af67529c63552103b124c4' \
      '8bbff7ebe16e7bd2b2f2b561aa53791da678a73d2777cc1ca4619ab6f721025098a1d5' \
      'a338592bf1e015468ec5a8fafc1fc9217feb5cb33597f3613a2165e9210360cfabc01d' \
      '52eaaeb3976a5de05ff0cfa76d0af42d3d7e1b4c233ee8a00655ed2103f571540c81fd' \
      '9dbf9622ca00cfe95762143f2eab6b65150365bb34ac533160432102bc2b4be1bca32b' \
      '9d97e2d6fb255504f4bc96e01aaca6e29bfa3f8bea65d8865855af672103ad6bb76e00' \
      'd124f07a22680e39debd4dc4bdb1aa4b893720dd05af3c50560fddada820a4d9338883' \
      '18a23c28fb5fc67aca8530524e2074b1d185dbf5b4db4ddb0642848868685174519c63' \
      '51670068000000000170f30500000000001976a914bce2fe0e49630a996cb9fe611e6b' \
      '9b7d1e4dc21188acb4ff6153'.htb
    )
    expect(tx2.verify_input_signature(0, tx1)).to be true
  end
end
