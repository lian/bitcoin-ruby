require_relative 'spec_helper.rb'

#
# following test cases are borrowed from
# https://github.com/bitcoinj/bitcoinj/blob/master/core/src/test/java/org/bitcoinj/core/BloomFilterTest.java
#
describe 'Bloom Filter' do
  before do
    @filter = Bitcoin::BloomFilter.new(3, 0.01, 2147483649)

    @filter.add_data('99108ad8ed9bb6274d3980bab5a85c048f0950c8'.htb)
    @filter.add_data('b5a2c786d9ef4658287ced5914b37a1b4aa32eee'.htb)
    @filter.add_data('b9300670b4c5366e95b2699e8b18bc75e5f729c5'.htb)
  end
  it "#contains?" do
    @filter.contains?('99108ad8ed9bb6274d3980bab5a85c048f0950c8'.htb).should == true
    @filter.contains?('19108ad8ed9bb6274d3980bab5a85c048f0950c8'.htb).should == false
    @filter.contains?('b5a2c786d9ef4658287ced5914b37a1b4aa32eee'.htb).should == true
  end
  it "#filter" do
    @filter.filter.bth.should == 'ce4299'
  end
end
