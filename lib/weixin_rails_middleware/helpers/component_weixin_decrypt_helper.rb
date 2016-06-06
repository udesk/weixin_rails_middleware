module WeixinRailsMiddleware
  module ComponentWeixinDecryptHelper
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

    def encrypt_body(content, time_stamp, nonce)
      encoding_aes_key = WeixinRailsMiddleware.config.encoding_aes_key
      aes_key = Base64.decode64(encoding_aes_key+"=")
      random = get_random_str.to_s
      msg_len = msg_length_pack(content).force_encoding("ASCII-8BIT")
      component_appid = COMPONENT_APPID.to_s
      aes_msg = random + msg_len.to_s + content.force_encoding("ASCII-8BIT") + component_appid
      cipher = OpenSSL::Cipher::AES.new(256, :CBC)
      cipher.encrypt
      cipher.key     = aes_key
      cipher.iv      = aes_key[0..16]
      Rails.logger.debug("#{__method__} aes_msg: #{aes_msg}")
      decrypted_data = cipher.update(aes_msg) + cipher.final
      msg_encrypt = Base64.encode64(decrypted_data)
      sign_str = [TOKEN, time_stamp, nonce, msg_encrypt].sort.join
      signature = Digest::SHA1.hexdigest(sign_str)
      res = %Q{<xml><Encrypt><![CDATA[#{msg_encrypt}]]></Encrypt><MsgSignature><![CDATA[#{signature}]]></MsgSignature><TimeStamp>#{time_stamp}</TimeStamp><Nonce><![CDATA[#{nonce}]]></Nonce></xml>}
      Rails.logger.debug("#{__method__} token/time_stamp/nonce/msg_encrypt/signature ====> #{TOKEN}/#{time_stamp}/#{nonce}/#{msg_encrypt}/#{signature}")
      Rails.logger.debug("#{__method__} res: #{res}")
      res
    end

    def get_random_str
      # 随机生成16位字符串
      return SecureRandom.hex 16
    end
    def msg_length_pack(msg)
      # 4位网络字节序
      return [msg.length].pack("N")
    end
  end
end
