module WeixinRailsMiddleware
  module ComponentWeixinDecryptHelper
    extend self
    def decrypt_body(aes_key, text, corpid)
      status = 200
      text        = Base64.decode64(text)
      text        = handle_cipher(:decrypt, aes_key, text)
      result      = ComponentPKCS7Encoder.decode(text)
      content     = result[16...result.length]
      len_list    = content[0...4].unpack("N")
      xml_len     = len_list[0]
      xml_content = content[4...4 + xml_len]
      from_corpid = content[xml_len+4...content.size]
      # TODO: refactor
      if corpid != from_corpid
        Rails.logger.debug("#{__FILE__}:#{__LINE__} Failure because #{corpid} != #{from_corpid}")
        status = 401
      end
      [xml_content, status]
    end

    def encrypt_body(aes_key, text, component_appid)
      text    = text.force_encoding("ASCII-8BIT")
      random  = SecureRandom.hex(8)
      msg_len = [text.length].pack("N")
      text    = "#{random}#{msg_len}#{text}#{component_appid}"
      text    = ComponentPKCS7Encoder.encode(text)
      text    = handle_cipher(:encrypt, aes_key, text)
      Base64.encode64(text)
    end

    def handle_cipher(action, aes_key, text)
      aes_key = Base64.decode64(aes_key+"=")
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.send(action)
      cipher.padding = 0
      cipher.key     = aes_key
      cipher.iv      = aes_key[0...16]
      cipher.update(text) + cipher.final
    end

    def generate_encrypt_message(token, encrypt_xml)
      msg = EncryptMessage.new
      msg.Encrypt = encrypt_xml
      msg.TimeStamp = Time.now.to_i.to_s
      msg.Nonce = SecureRandom.hex(8)
      msg.MsgSignature = generate_msg_signature(token, encrypt_xml, msg)
      msg.to_xml
    end

    def generate_msg_signature(token, encrypt_msg, msg)
      sort_params = [encrypt_msg, token, msg.TimeStamp, msg.Nonce].sort.join
      Digest::SHA1.hexdigest(sort_params)
    end

    def valid_msg_signature(token, time_stamp, nonce, msg_encrypt, msg_signature)
      sign_str = [token, time_stamp, nonce, msg_encrypt].sort.join
      signature = Digest::SHA1.hexdigest(sign_str)
      Rails.logger.debug("#{__method__} signature/msg_signature: #{signature}/#{msg_signature}")
      return signature == msg_signature
    end

  end
end
