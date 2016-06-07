module WeixinRailsMiddleware
  class WeixinController < ActionController::Base
    include ReplyWeixinMessageHelper
    include ComponentWeixinDecryptHelper

    skip_before_filter :verify_authenticity_token
    before_filter :initialize_adapter, only: [:index, :reply, :component_reply]
    before_filter :check_weixin_legality, only: [:index, :reply]
    before_filter :set_weixin_public_account, only: [:reply, :component_reply]
    before_filter :set_weixin_message, only: :reply
    before_filter :set_weixin_decrypt_message, only: :component_reply
    before_filter :set_keyword, only: :reply

    def index
    end

    def reply
    end

    # 第三方平台
    def component_reply
    end

    protected

      def initialize_adapter
        @weixin_adapter ||= WexinAdapter.init_with(params)
      end

      def check_weixin_legality
        check_result = @weixin_adapter.check_weixin_legality
        valid = check_result.delete(:valid)
        render check_result if action_name == "index"
        return valid
      end

      ## Callback
      # e.g. will generate +@weixin_public_account+
      def set_weixin_public_account
        @weixin_public_account ||= @weixin_adapter.current_weixin_public_account
      end

      def set_weixin_message
        # Get the current weixin message
        @weixin_message ||= Message.factory(request.body.read)
      end

      def set_keyword
        @keyword = @weixin_message.Content    || # 文本消息
                   @weixin_message.EventKey   || # 事件推送
                   @weixin_message.Recognition # 接收语音识别结果
      end

      # http://apidock.com/rails/ActionController/Base/default_url_options
      def default_url_options(options={})
        { weichat_id: @weixin_message.FromUserName }
      end

      def set_weixin_decrypt_message
        param_xml = request.body.read
        Rails.logger.debug("DEBUG WECHAT MESSAGE: #{param_xml}")
        hash = MultiXml.parse(param_xml)['xml']
        @body_xml = OpenStruct.new(hash)
        body_message = decrypt_body(ENCODING_AES_KEY, @body_xml.Encrypt, COMPONENT_APPID)
        Rails.logger.debug("DEBUG WECHAT BODY_MESSAGE: #{body_message}")
        @weixin_message ||= Message.factory(body_message[0])
      end

  end
end
