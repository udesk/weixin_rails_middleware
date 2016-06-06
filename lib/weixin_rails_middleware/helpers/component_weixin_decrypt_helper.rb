module WeixinRailsMiddleware
  module ComponentWeixinDecryptHelper
    extend self
    def decrypt_body(content)

      encoding_aes_key = WeixinRailsMiddleware.config.encoding_aes_key
      xml_hash = MultiXml.parse(content)['xml']
      aes_msg = Base64.decode64(xml_hash["Encrypt"])
      aes_key = Base64.decode64(encoding_aes_key+"=")
      cipher = OpenSSL::Cipher::AES.new(256, :CBC)
      cipher.decrypt
      # must set up padding
      cipher.padding = 0
      cipher.key     = aes_key
      cipher.iv      = aes_key[0..16]
      decrypted_data = cipher.update(aes_msg) + cipher.final
      random = decrypted_data[0, 16] # 16 位随机数
      msg_len = decrypted_data[16, 4] # 4个字节 msg长度
      msg = decrypted_data[20,  msg_len.unpack("N").first]
      msg
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
