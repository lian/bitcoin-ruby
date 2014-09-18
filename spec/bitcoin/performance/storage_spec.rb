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
      @fake_chain = FakeBlockchain.new 10
    end

    it "block storage" do
      blocks = (0..10).to_a.map{|i|  @fake_chain.block(i) }

      bm = Benchmark.measure do
        bm = Benchmark.bm do |b|
          blocks.each.with_index do |blk,i|
            b.report("storing fake block ##{i}") do
              depth, chain = @store.new_block blk
              chain.should == 0
            end
          end
        end
      end
      puts '-'*80
      puts "TOTAL #{bm.format}"
    end


  end
end
