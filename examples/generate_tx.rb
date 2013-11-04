$:.unshift( File.expand_path("../../lib", __FILE__) )
require 'bitcoin'

# p Bitcoin.generate_address # returns address, privkey, pubkey, hash160

prev_tx = Bitcoin::Protocol::Tx.from_json_file('baedb362adba39753a7d2c58fd3dc4897a1b479859f707a819f096696f3facad.json') # <- redeeming transaction input fetchted by for example simple_network_monitor_and_util.rb
prev_tx_output_index = 0
value = prev_tx.outputs[prev_tx_output_index].value
#value = 1337 # maybe change the value (eg subtract for fees)


tx = Bitcoin::Protocol::Tx.new
tx.add_in Bitcoin::Protocol::TxIn.new(prev_tx.binary_hash, prev_tx_output_index, 0)

tx.add_out Bitcoin::Protocol::TxOut.value_to_address(value, "1MiQ3zD3hzZBZ4cUDfPd8Eqnjcedkwt5jy") # <- dest address (our donation address)

# if all in and outputs are defined, start signing inputs.
key = Bitcoin.open_key("9b2f08ebc186d435ffc1d10f3627f05ce4b983b72c76b0aee4fcce99e57b0342") # <- privkey
sig = Bitcoin.sign_data(key, tx.signature_hash_for_input(0, prev_tx))
tx.in[0].script_sig = Bitcoin::Script.to_signature_pubkey_script(sig, [key.public_key_hex].pack("H*"))
#tx.in[0].add_signature_pubkey_script(sig, key.public_key_hex)

# finish check
tx = Bitcoin::Protocol::Tx.new( tx.to_payload )
p tx.hash
p tx.verify_input_signature(0, prev_tx) == true

puts "json:\n"
puts tx.to_json # json
puts "\nhex:\n"
puts tx.to_payload.unpack("H*")[0] # hex binary

# use this json file for example with `ruby simple_network_monitor_and_util.rb send_tx=<filename>` to push/send it to the network
File.open(tx.hash + ".json", 'wb'){|f| f.print tx.to_json }
