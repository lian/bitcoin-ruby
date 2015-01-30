#
# Ruby Example of the 'proof of work' explanation
# from https://en.bitcoin.it/wiki/Proof_of_work
#
# note: block data passed to do_work is simplified.
#       bitcoin blockchain is more complex too.
#

require 'digest/sha2'


def do_work(data, target, nonce=0)
  found = nil
  until found
      d = data + [nonce].pack("I")
      h = Digest::SHA256.hexdigest( Digest::SHA256.digest( d ) ).to_i(16)

      if h <= target
        found = [h.to_s(16).rjust(64, '0'), nonce]
        break
      end

      nonce+=1
  end
  found
end


def next_block(blocks, target, data)
  block_id    = blocks.size
  last_block  = last_hash(blocks)
  data        = last_block + " " + data

  hash, nonce = nil, nil

  work_time   = t{   hash, nonce = do_work(data, target.to_i(16))         }
  verify_time = t{   hash, nonce = do_work(data, target.to_i(16), nonce)  }

  print_block( block_id, target, data, nonce, hash, work_time, verify_time )

  [ hash, nonce, target, data, work_time, verify_time ]
end



def print_block(*args)
  puts <<-TEXT % args
-------------------- block %s
  target: %s
   data: '%s' + %s (nonce)
   found: %s

  time:
    took: %f
  verify: %f

  TEXT
end

def last_hash(blocks)
  if blocks.empty?
    "0000000000000000000000000000000000000000000000000000000000000000"
  else
    blocks.last[0]
  end
end

def t; x = Time.now; yield; Time.now - x; end



if $0 == __FILE__

  target = "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  blocks = []


  blocks << next_block( blocks, target, "hello ruby" )
  blocks << next_block( blocks, target, "this is" )
  blocks << next_block( blocks, target, "a blockchain" )
  blocks << next_block( blocks, target, "and proof-of-work" )
  blocks << next_block( blocks, target, "example!" )


  puts <<-TEXT % [ blocks.size, target, blocks.inject(0){|e,i| e+=i[-2] }, blocks.inject(0){|e,i| e+=i[-1] } ]
-------------------- blockchain time summary
       chain length: %d
         difficulty: %s
    total work time: %f
  total verify time: %f

  TEXT

end


__END__
% ruby concept-examples/blockchain-pow.rb

-------------------- block 0
  target: 00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
   data: '0000000000000000000000000000000000000000000000000000000000000000 hello ruby' + 1373297 (nonce)
   found: 00000b1522d81f532d5e33c4fd22537b66f1ff052315b47000e61496510ceaa2

  time:
    took: 41.073509
  verify: 0.000060

-------------------- block 1
  target: 00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
   data: '00000b1522d81f532d5e33c4fd22537b66f1ff052315b47000e61496510ceaa2 this is' + 2877742 (nonce)
   found: 0000006f3ac527d921b57a88d3d6e5793f0813d4fafb17e0b31456ad1d652e05

  time:
    took: 86.098830
  verify: 0.000058

-------------------- block 2
  target: 00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
   data: '0000006f3ac527d921b57a88d3d6e5793f0813d4fafb17e0b31456ad1d652e05 a blockchain' + 255946 (nonce)
   found: 000000196f5e67ca66f281cf6b884b312984173651ddf12e151db6b1428a882b

  time:
    took: 7.648288
  verify: 0.000057

-------------------- block 3
  target: 00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
   data: '000000196f5e67ca66f281cf6b884b312984173651ddf12e151db6b1428a882b and proof-of-work' + 2930300 (nonce)
   found: 00000a197372b28e93479598afa504c92bcb50af2c5c6893686e91ce47ad0747

  time:
    took: 87.530473
  verify: 0.000058

-------------------- block 4
  target: 00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
   data: '00000a197372b28e93479598afa504c92bcb50af2c5c6893686e91ce47ad0747 example!' + 85074 (nonce)
   found: 00000a406be803d6a02c5aded00c159b664fe11ed768dbcb3ecb7b2ec6257706

  time:
    took: 2.555810
  verify: 0.000058

-------------------- blockchain time summary
       chain length: 5
         difficulty: 00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    total work time: 224.906909
  total verify time: 0.000292


