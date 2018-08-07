# encoding: ascii-8bit

module Bitcoin
  # This module includes (almost) everything necessary to add dogecoin support
  # to bitcoin-ruby. When switching to a :dogecoin network, it will load its
  # functionality into the Script class.
  # The only things not included here should be parsing the AuxPow, which is
  # done in Protocol::Block directly, and passing the txout to #store_doge from
  # the storage backend.
  module Dogecoin
    def self.load
      Bitcoin::Util.class_eval { include Util }
    end

    # fixed reward past the 600k block
    POST_600K_REWARD = 10_000 * Bitcoin::COIN

    # Dogecoin-specific Script methods for parsing and creating of dogecoin scripts,
    # as well as methods to extract address, doge_hash, doge and value.
    module Util
      # rubocop:disable CyclomaticComplexity,PerceivedComplexity
      def self.included(base)
        base.constants.each { |c| const_set(c, base.const_get(c)) unless constants.include?(c) }
        base.class_eval do
          def block_creation_reward(block_height)
            reward_scaler = 2**(block_height / Bitcoin.network[:reward_halving].to_f).floor
            if block_height < Bitcoin.network[:difficulty_change_block]
              # Dogecoin early rewards were random, using part of the hash of the
              # previous block as the seed for the Mersenne Twister algorithm.
              # Given we don't have previous block hash available, and this value is
              # functionally a maximum (not exact value), I'm using the maximum the random
              # reward generator can produce and calling it good enough.
              Bitcoin.network[:reward_base] / reward_scaler * 2
            elsif block_height < 600_000
              Bitcoin.network[:reward_base] / reward_scaler
            else
              POST_600K_REWARD
            end
          end

          def block_new_target(prev_height, prev_block_time, prev_block_bits, last_retarget_time)
            new_difficulty_protocol = (prev_height + 1) >= Bitcoin.network[:difficulty_change_block]

            # target interval for block interval in seconds
            retarget_time = Bitcoin.network[:retarget_time]

            if new_difficulty_protocol
              # what is the ideal interval between the blocks
              retarget_time = Bitcoin.network[:retarget_time_new]
            end

            # actual time elapsed since last retarget
            actual_time = prev_block_time - last_retarget_time

            if new_difficulty_protocol
              # DigiShield implementation - thanks to RealSolid & WDC for this code
              # We round always towards zero to match the C++ version
              actual_time = if actual_time < retarget_time
                              retarget_time + ((actual_time - retarget_time) / 8.0).ceil
                            else
                              retarget_time + ((actual_time - retarget_time) / 8.0).floor
                            end
              # amplitude filter - thanks to daft27 for this code
              min = retarget_time - (retarget_time / 4)
              max = retarget_time + (retarget_time / 2)
            elsif prev_height + 1 > 10_000
              min = retarget_time / 4
              max = retarget_time * 4
            elsif prev_height + 1 > 5000
              min = retarget_time / 8
              max = retarget_time * 4
            else
              min = retarget_time / 16
              max = retarget_time * 4
            end

            actual_time = min if actual_time < min
            actual_time = max if actual_time > max

            # It could be a bit confusing: we are adjusting difficulty of the previous block,
            # while logically we should use difficulty of the previous 2016th block ("first")

            prev_target = decode_compact_bits(prev_block_bits).to_i(16)

            new_target = prev_target * actual_time / retarget_time
            if new_target < Bitcoin.decode_compact_bits(
              Bitcoin.network[:proof_of_work_limit]
            ).to_i(16)
              encode_compact_bits(new_target.to_s(16))
            else
              Bitcoin.network[:proof_of_work_limit]
            end
          end
        end
      end
      # rubocop:enable CyclomaticComplexity,PerceivedComplexity
    end
  end
end
