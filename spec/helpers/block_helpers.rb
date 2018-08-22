# frozen_string_literal: true

# Helpers for block construction using the builder abstraction.
module BlockHelpers
  # Network configuration where mining a block is possible
  Bitcoin::NETWORKS[:spec] = {
    project: :bitcoin,
    magic_head: 'spec',
    address_version: '6f',
    p2sh_version: 'c4',
    privkey_version: 'ef',
    default_port: 48_333,
    protocol_version: 70_001,
    max_money: 21_000_000 * 100_000_000,
    dns_seeds: [],
    genesis_hash: '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943',
    proof_of_work_limit: 553_713_663,
    alert_pubkeys: [],
    known_nodes: [],
    checkpoints: {},
    min_tx_fee: 10_000,
    min_relay_tx_fee: 10_000,
    free_tx_bytes: 1_000,
    dust: 1_000_000,
    per_dust_fee: false
  }

  # rubocop:disable Metrics/ParameterLists
  def create_block(prev,
                   store = true,
                   transaction = [],
                   key = Bitcoin::Key.generate,
                   coinbase_value = 50e8,
                   opts = {})
    @store ||= nil
    opts[:bits] ||= Bitcoin.network[:proof_of_work_limit]

    block = build_block(Bitcoin.decode_compact_bits(opts[:bits])) do |b|
      b.time opts[:time] if opts[:time]
      b.prev_block prev
      b.tx do |t|
        t.input(&:coinbase)
        t.output do |o|
          o.value coinbase_value
          o.script { |s| s.recipient key.addr }
        end
      end

      transaction.each do |cb|
        b.tx { |t| cb.call(t) }
      end
    end

    @store.store_block(block) if !@store.nil? && store
    block
  end
  # rubocop:enable Metrics/ParameterLists
end
