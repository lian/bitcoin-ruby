# encoding: ascii-8bit

require_relative '../spec_helper'
require_relative '../helpers/fake_blockchain'
require 'benchmark'

[
 [:sequel, :postgres]
].compact.each do |options|

  next  unless storage = setup_db(*options)

  describe "#{storage.backend_name} block storage" do

    before do
      @store = storage
      @store.reset
      @store.log.level = :error
      class Bitcoin::Validation::Block; def difficulty; true; end; end

      FakeBlockchain.prepare
    end

    it "block storage" do

      bm = Benchmark.measure do
        bm = Benchmark.bm do |b|
          10.times do |i|
            b.report("storing fake block ##{i}") { @store.new_block FakeBlockchain.block(i) }
          end
        end
      end
      puts '-'*80
      puts "TOTAL #{bm.format}"

      should.satisfy { "human" }
    end


  end
end
