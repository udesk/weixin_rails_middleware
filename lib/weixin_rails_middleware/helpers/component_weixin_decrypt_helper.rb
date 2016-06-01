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
  end
end
