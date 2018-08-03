# encoding: ascii-8bit

module Bitcoin
  module Protocol
    Reject = Struct.new(:message, :ccode, :reason, :data) do
      CCODE_TABLE = {
        0x01 => :malformed,
        0x10 => :invalid,
        0x11 => :obsolete,
        0x12 => :duplicate,
        0x40 => :nonstandard,
        0x41 => :dust,
        0x42 => :insufficientfee,
        0x43 => :checkpoint
      }.freeze

      def self.parse(payload)
        message, payload = Bitcoin::Protocol.unpack_var_string(payload)
        ccode,   payload = payload.unpack('Ca*')
        reason,  payload = Bitcoin::Protocol.unpack_var_string(payload)
        data =   payload

        code = CCODE_TABLE[ccode] || ccode
        new(message, code, reason, data)
      end

      def tx_hash
        message == 'tx' && self[:data].reverse.bth
      end

      def block_hash
        message == 'block' && self[:data].reverse.bth
      end
    end
  end
end
