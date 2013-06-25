# encoding: ascii-8bit

module Bitcoin
module Protocol

  class Alert < Struct.new(:version, :relay_until, :expiration, :id, :cancel, :set_cancel,
                           :min_ver, :max_ver, :set_sub_ver, :priority, :comment, :status_bar, :reserved)

    attr_accessor :payload, :signature

    def initialize(values, alert_payload=nil, alert_signature=nil)
      @payload, @signature = alert_payload, alert_signature
      super(*values)
    end

    def valid_signature?
      return false unless @payload && @signature
      hash = Digest::SHA256.digest(Digest::SHA256.digest(@payload))
      Bitcoin.network[:alert_pubkeys].any?{|public_key| Bitcoin.verify_signature(hash, @signature, public_key) }
    end


    def self.parse(payload)
      count,             payload = Bitcoin::Protocol.unpack_var_int(payload)
      alert_payload,     payload = payload.unpack("a#{count}a*")
      count,             payload = Bitcoin::Protocol.unpack_var_int(payload)
      alert_signature,   payload = payload.unpack("a#{count}a*")

      version, relay_until, expiration, id, cancel, payload = alert_payload.unpack("VQQVVa*")

      set_cancel,        payload = Bitcoin::Protocol.unpack_var_int_array(payload)
      min_ver, max_ver,  payload = payload.unpack("VVa*")
      set_sub_ver,       payload = Bitcoin::Protocol.unpack_var_string_array(payload)
      priority,          payload = payload.unpack("Va*")
      comment,           payload = Bitcoin::Protocol.unpack_var_string(payload)
      status_bar,        payload = Bitcoin::Protocol.unpack_var_string(payload)
      reserved,          payload = Bitcoin::Protocol.unpack_var_string(payload)

      values = [ version, relay_until, expiration, id, cancel, set_cancel, min_ver, max_ver, set_sub_ver, priority, comment, status_bar, reserved ]

      new(values, alert_payload, alert_signature)
    end
  end

end
end
