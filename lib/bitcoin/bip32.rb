# encoding: ascii-8bit

module Bitcoin
  module BIP32
    class Node
      attr_reader :seed, :seed_hash, :bitcoin_key, :chain_code_hex, :index, :depth
      
      def is_private?
        index >= 0x80000000 || index < 0
      end
      
      def index_hex(i = index)
        if i < 0
          [i].pack('l>').unpack('H*').first
        else
          i.to_s(16).rjust(8, "0")
        end
      end
      
      def private_derivation_message(i)
        "\x00" + [ @bitcoin_key.priv ].pack("H*") + [i].pack("N")
      end
      
      def public_derivation_message(i)
        #[ @bitcoin_key.pub_uncompressed ].pack("H*") + [i].pack("N") # TODO: check
        [ @bitcoin_key.pub_compressed ].pack("H*") + [i].pack("N")
      end

      def derive_private_key(i = 0)
        message = i >= 0x80000000 || i < 0 ? private_derivation_message(i) : public_derivation_message(i)
        hash = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA512.new, [@chain_code_hex].pack("H*"), message)
        left_int = left_from_hash(hash)

        order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".to_i(16)
        raise InvalidKeyForIndex, 'greater than or equal to order' if left_int >= order
        child_private_key = (left_int + @bitcoin_key.priv.to_i(16)) % order
        raise InvalidKeyForIndex, 'equal to zero' if child_private_key == 0
        child_chain_code_hex = right_from_hash_hex(hash)
        return child_private_key.to_s(16).rjust(64, '0'), child_chain_code_hex
      end

      def derive_public_key(i = 0)
        raise PrivatePublicMismatch if i >= 0x80000000
        message = public_derivation_message(i)
        hash = hmac_sha512 hex_to_bytes(chain_code_hex), message
        left_int = left_from_hash(hash)
        raise InvalidKeyForIndex, 'greater than or equal to order' if left_int >= MoneyTree::Key::ORDER # very low probability
        factor = BN.new left_int.to_s
        child_public_key = public_key.uncompressed.group.generator.mul(factor).add(public_key.uncompressed.point).to_bn.to_i
        raise InvalidKeyForIndex, 'at infinity' if child_public_key == 1/0.0 # very low probability
        child_chain_code = right_from_hash(hash)
        return child_public_key, child_chain_code
      end
      
      def left_from_hash(hash)
        hash[0..31].unpack("H*")[0].to_i(16)
      end
      
      def right_from_hash(hash)
        hash[32..-1].unpack("H*")[0].to_i(16)
      end

      def left_from_hash_hex(hash)
        hash[ 0..31].unpack("H*")[0]
      end
      
      def right_from_hash_hex(hash)
        hash[32..-1].unpack("H*")[0]
      end

      def to_fingerprint
        pub = @bitcoin_key.pub_compressed
        #Digest::RIPEMD160.hexdigest(Digest::SHA256.digest([pub].pack("H*")))[0..7]
        Bitcoin.hash160(pub)[0..7] # TODO: check
      end

      def parent_fingerprint
        @parent_fingerprint || (@depth == 0 ? '00000000' : @parent.to_fingerprint)
      end

      def to_serialized_hex(type = :public)
        raise PrivatePublicMismatch if type.to_sym == :private && !@bitcoin_key.priv
        version_key = type.to_sym == :private ? :extended_privkey_version : :extended_pubkey_version
        hex  = Bitcoin.network[version_key]  # version (4 bytes)
        hex += [@depth].pack("C").unpack("H*")[0] # depth (1 byte)
        hex += parent_fingerprint            # fingerprint of key (4 bytes)
        hex += index_hex(@index)             # child number i (4 bytes)
        hex += @chain_code_hex
        hex += type.to_sym == :private ? "00#{@bitcoin_key.priv}" : @bitcoin_key.pub_compressed
      end
      
      def to_serialized_address(type = :public)
        version, hex = to_serialized_hex(type).unpack("a8a*")
        Bitcoin.encode_address(hex, version)
      end

      def to_address(compressed=true)
        @bitcoin_key.addr
      end
      
      def subnode(i = 0, opts = {})
        if !@bitcoin_key.priv
          child_public_key, child_chain_code = derive_public_key(i)
          child_public_key = MoneyTree::PublicKey.new child_public_key, network: network_key
        else
          child_private_key, child_chain_code = derive_private_key(i)
          bitcoin_key = Bitcoin::Key.new(child_private_key, nil, true); bitcoin_key.pub
        end

        Bitcoin::BIP32::Node.new depth: @depth+1, index: i, parent: self,
                                 private_key: bitcoin_key.priv || nil,
                                 public_key: bitcoin_key.pub_compressed,
                                 chain_code_hex: child_chain_code
      end

      def parse_index(path_part)
        is_prime = %w(p ').include? path_part[-1]
        i = path_part.to_i
        
        i = if i < 0
          i
        elsif is_prime
          i | 0x80000000
        else
          i & 0x7fffffff
        end
      end
      
      def strip_private_info!
        # TODO
        @private_key = nil
      end
      
      # path: a path of subkeys denoted by numbers and slashes. Use
      #     p or i<0 for private key derivation. End with .pub to force
      #     the key public.
      # 
      # Examples:
      #     1p/-5/2/1 would call subkey(i=1, is_prime=True).subkey(i=-5).
      #         subkey(i=2).subkey(i=1) and then yield the private key
      #     0/0/458.pub would call subkey(i=0).subkey(i=0).subkey(i=458) and
      #         then yield the public key
      # 
      # You should choose either the p or the negative number convention for private key derivation.
      def node_for_path(path)
        force_public = path[-4..-1] == '.pub'
        path = path[0..-5] if force_public
        parts = path.split('/')
        nodes = []
        parts.each_with_index do |part, depth|
          if part =~ /m/i
            nodes << self
          else
            i = parse_index(part)
            node = nodes.last || self
            nodes << node.subnode(i)
          end
        end
        if force_public or parts.first == 'M'
          node = nodes.last
          node.strip_private_info!
          node
        else
          nodes.last
        end
      end

      def initialize(opts = {})
        #p opts.reject{|k,v| k == :parent }
        @depth  = opts[:depth] || 0
        @index  = opts[:index] || 0
        @parent = opts[:parent] || nil
        @parent_fingerprint = opts[:parent_fingerprint] || nil

        if opts[:private_key] || opts[:public_key]
          raise ArgumentError, 'chain code required' unless opts[:chain_code_hex]
          @chain_code_hex = opts[:chain_code_hex]
          if opts[:private_key]
            @bitcoin_key = Bitcoin::Key.new(opts[:private_key], nil, true)
            @bitcoin_key.pub
          else opts[:public_key]
            @bitcoin_key = Bitcoin::Key.new(nil, opts[:public_key], true)
          end
        else
          raise ArgumentError
        end
      end

      def self.from_serialized_address(address)
        hex = Bitcoin.decode_base58(address)
        checksum = hex.slice!(-8..-1)
        raise "EncodingError" unless checksum == Bitcoin.checksum(hex)

        version, depth, parent_fingerprint, index, chain_code, key = hex.unpack("a8a2a8a8a64a*")

        opts = {
          depth: depth.to_i(16),
          parent_fingerprint: parent_fingerprint,
          index: index.to_i(16),
          chain_code_hex: chain_code 
        }

        case version
        when Bitcoin.network[:extended_privkey_version]
          opts[:private_key] = key[2..-1] if key[0..1] == "00"
        when Bitcoin.network[:extended_pubkey_version]
          #opts[:public_key] = key if %w(04 03 02).include?(key[0..1]) # TODO: check
          opts[:public_key] = key if %w(03 02).include?(key[0..1])
        else
          raise ArgumentError, 'Public or private key data does not match version type: %s' % version
        end

        new(opts)
      end


    end


    class Master < Node
      def initialize(seed)
        @depth, @index = 0, 0

        @seed = seed # binary
        @seed_hash = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA512.new, "Bitcoin seed", @seed)
        #raise "SeedGeneration::ImportError" unless seed_valid?(@seed_hash)

        private_key, @chain_code_hex = left_from_hash_hex(seed_hash), right_from_hash_hex(seed_hash)
        @bitcoin_key = Bitcoin::Key.new(private_key, nil, compressed: true)
        @bitcoin_key.pub
      end
      
      def is_private?; true; end
    end


  end
end

require "bundler/setup"
require "bitcoin"

if $0 == __FILE__
  seed = ["d0bc7826e57dee7ffbb9fa0e152ccf434b5637bba0134985478db6979b8a2efe0150b53590747a7c6aa7f72ad3e27aee8687d6df5e4c890d86751c94439819f4"].pack("H*")
  master = Bitcoin::BIP32::Master.new(seed)
  p master.to_serialized_hex(:public) == "0488b21e000000000000000000e906cd71552b257cc413ed9782cf9bdc1516673b773a38a1f7f446374007a8960296063869d7f60f52afb232a06dcd58f597e5e255ecbafcd32df262bd955c7f37"
  p master.chain_code_hex == "e906cd71552b257cc413ed9782cf9bdc1516673b773a38a1f7f446374007a896"
  p master.bitcoin_key.pub_compressed == "0296063869d7f60f52afb232a06dcd58f597e5e255ecbafcd32df262bd955c7f37"
  p master.to_serialized_address == "xpub661MyMwAqRbcGrzge1szyTmc2gy7QVx8T3feUFJukjutbshPGB81pjNzdoaq8ftf7rVsK1BAg8YGGingusCdxm5q3ZNJqd1DMsnHeUtMtDi"
  p master.to_serialized_address(:private) == "xprv9s21ZrQH143K4NvDXzLzcKpsUf8d13EH5pk3fruJCQNuj5NEidomGw4WnY8w6RkHah3nEURamaUsPcaV927PAiSjHvVTbuaEMFA6Hbdx63T"

  node = master.node_for_path "m/44'/0'/0'/0/0"
  p node.depth == 5
  p node.chain_code_hex == "35a1635712c3ba60e92280b7994d879e114d8dfec93b2d907d7158f51038b5c5"
  p node.to_address == "13Z7SARqcSr9BKmCKVbyjeYPod4LEGqM4L"
  p node.to_address

  master2 = Bitcoin::BIP32::Node.from_serialized_address( master.to_serialized_address(:private) )
  p master2.to_serialized_hex(:public) == "0488b21e000000000000000000e906cd71552b257cc413ed9782cf9bdc1516673b773a38a1f7f446374007a8960296063869d7f60f52afb232a06dcd58f597e5e255ecbafcd32df262bd955c7f37"
  p master2.chain_code_hex == "e906cd71552b257cc413ed9782cf9bdc1516673b773a38a1f7f446374007a896"
  p master2.bitcoin_key.pub_compressed == "0296063869d7f60f52afb232a06dcd58f597e5e255ecbafcd32df262bd955c7f37"
  p master2.to_serialized_address == "xpub661MyMwAqRbcGrzge1szyTmc2gy7QVx8T3feUFJukjutbshPGB81pjNzdoaq8ftf7rVsK1BAg8YGGingusCdxm5q3ZNJqd1DMsnHeUtMtDi"
  p master2.to_serialized_address(:private) == "xprv9s21ZrQH143K4NvDXzLzcKpsUf8d13EH5pk3fruJCQNuj5NEidomGw4WnY8w6RkHah3nEURamaUsPcaV927PAiSjHvVTbuaEMFA6Hbdx63T"

  node = master2.node_for_path "m/44'/0'/0'/0/0"
  p node.depth == 5
  p node.chain_code_hex == "35a1635712c3ba60e92280b7994d879e114d8dfec93b2d907d7158f51038b5c5"
  p node.to_address == "13Z7SARqcSr9BKmCKVbyjeYPod4LEGqM4L"
  p node.to_address

  ## from: http://bip32.org/
  # litecoin
  #master3 = Bitcoin::BIP32::Node.from_serialized_address( "Ltpv75Xw1ZLi1HnnfDJPhWwhC7ZxfZ1XFt8ukDKnKULcNowk7wUBYdt54AmuwQkVGziWRsr1MBt7BooigNgv62oVTVxudx45ZiSA9vrs8h58bfu" )
  #master3 = Bitcoin::BIP32::Node.from_serialized_address( "Ltub2WiGcLmFFSKkH61Dx8S5GhQB77hiL8hZpjRozT6uJzjLiJfFsYvW4mtBBoTVv1jFq6XsKCXyti6pThqWzaGHJupvvG8L29XHXhy3cNjiHf1" )
  # litecoin testnet
  #master3 = Bitcoin::BIP32::Node.from_serialized_address( "ttpv9ATh1zJgV72nBiUqbMz5petg9XzPdsPoqjKesyLGf5kVsTbsYqejKVWxH9W7hv543tbfiw3uXDu4kDN6pgYdtfdSsrpeFghaAH2WGpLyu8B" )
  #master3 = Bitcoin::BIP32::Node.from_serialized_address( "ttub4be2cmjDjFZjobBfqyUTuEitb6gai7xTvFRgYx6ZbGY6TpnwskhAL6dDXYD8Lw5oT7HXgwhnE8CAXYWhjE1Rk5VUAAtti7nhY48gkSkk2xu" )
  # dogecoin
  #master3 = Bitcoin::BIP32::Node.from_serialized_address( "dgpv55uxPmfvLwipv6wVchd4j53Gp4A1ooJETJe9aZy3TbdMz5KDkSQMGt4nckpKUS9oQvxBbUHka383MggxUDrVY1rLqZ38Q8X3MAY9dN4ZZQG" )
  #master3 = Bitcoin::BIP32::Node.from_serialized_address( "dgub8pnyjTbou6PACxbeewF2qvasGcXedvKwjuRMjgN2FigNY8RvACx7vBUSC1STdajUEceBAxqjegfPNLnReQpaTou4epeNsjYMPoVKRNZLwYA" )
  # dogecoin testnet
  #master3 = Bitcoin::BIP32::Node.from_serialized_address( "tgpv1ehEDsEKHAjezZrwLTHqp7kSNafHBEheyunGqMkeHm29ptc2TTNSy8dUbzGyvvPh74i9E8L36DC3PewYz2ZQRAufKgxV9csAkBdq9jTNnTb" )
  #master3 = Bitcoin::BIP32::Node.from_serialized_address( "tgub5PaFZZACqKPzHRX6NguovyJ2q92v1MjNGWZUzU9d5t5ANwiisDvDcS38BEu864yMvkQ8oct2ArjPQK32ADXVLxxP8xZjdDtUnpazwke6EZV" )

end
