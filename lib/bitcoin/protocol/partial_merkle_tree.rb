class Bitcoin::Protocol::PartialMerkleTree
  Node = Struct.new(:value, :left, :right, :width_idx)

  BIT_MASK = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]

  def initialize(total_txs, hashes, flags)
    @total_txs, @flags = total_txs, flags
    @hashes = hashes.map{|h| h.reverse_hth }
    @visit_idx = 0
  end

  def tx_hashes
    @leaves.reject{|n| n.value.nil? }.map{|n| n.value }
  end

  def build_tree
    lay = @leaves = @total_txs.times.map{ Node.new(nil, nil, nil) }
    while lay.size > 1
      lay = lay.each_slice(2).map do |left, right|
        Node.new(nil, left, right)
      end
    end
    return lay[0]
  end

  def current_flag
    @flags[@visit_idx / 8].ord & BIT_MASK[@visit_idx % 8] == 0
  end

  def root
    @root ||= build_tree
  end

  def set_value(node = root)
    if current_flag || (node.left.nil? && node.right.nil?)
      node.value = @hashes.shift
      return
    end

    if node.left
      @visit_idx += 1
      set_value(node.left)
    end
    if node.right
      @visit_idx += 1
      set_value(node.right)
    end

    right = node.right || node.left
    node.value = Bitcoin.bitcoin_mrkl(node.left.value, right.value)

    return
  end

  def valid_tree?(mrkl_root_hash)
    return false unless @hashes.empty?
    return false if ((@visit_idx + 1)/8.0).ceil != @flags.length
    return false if mrkl_root_hash != root.value
    return true
  end
end
