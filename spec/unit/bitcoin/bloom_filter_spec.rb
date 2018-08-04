# frozen_string_literal: true

require 'spec_helper'

describe Bitcoin::BloomFilter do
  let(:item1) { '99108ad8ed9bb6274d3980bab5a85c048f0950c8' }
  let(:item2) { 'b5a2c786d9ef4658287ced5914b37a1b4aa32eee' }
  let(:item3) { 'b9300670b4c5366e95b2699e8b18bc75e5f729c5' }

  subject { Bitcoin::BloomFilter.new(3, 0.01, 2_147_483_649) }

  describe '#contains?' do
    it 'contains items that have been added to it' do
      subject.add_data(item1.htb)
      subject.add_data(item2.htb)
      subject.add_data(item3.htb)

      expect(subject).to be_contains(item1.htb)
      expect(subject).to be_contains(item2.htb)
      expect(subject).to be_contains(item3.htb)
    end
  end

  describe '#filter' do
    it 'produces the expected filter' do
      subject.add_data(item1.htb)
      subject.add_data(item2.htb)
      subject.add_data(item3.htb)

      expect(subject.filter.bth).to eq('ce4299')
    end
  end
end
