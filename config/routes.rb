WeixinRailsMiddleware::Engine.routes.draw do
  get  'weixin/:weixin_secret_key', to: 'weixin#index', as: :weixin_server
  post 'weixin/:weixin_secret_key', to: 'weixin#reply', as: :weixin_reply
  # 第三方回调接口 授权后代替公众号实现业务
  post 'weixin/:weixin_secret_key/reply', to: 'weixin#component_reply', as: :weixin_component_reply
end
