require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class VSTS < OmniAuth::Strategies::OAuth2
      option :name, 'vsts'
      option :authorize_params, {:response_type => 'Assertion'}
      option :token_params, {
        :client_assertion_type => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        :grant_type => 'urn:ietf:params:oauth:grant-type:jwt-bearer'
      }

      option :client_options, {
        :site => 'https://app.vssps.visualstudio.com',
        :authorize_url => '/oauth2/authorize',
        :token_url =>  '/oauth2/token'
      }

      def callback_url
        full_host + script_name + callback_path
      end

      def authorize_params
        super.tap do |params|
          %w[client_options].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end

      uid { raw_info['id'].to_s }
      
      info do
        {
          'name' => raw_info['displayName'],
          'email' => raw_info['emailAddress'],
          'public_alias' => raw_info['publicAlias']
        }
      end

      extra do
        {:raw_info => raw_info }
      end

      def raw_info
        @raw_info ||= access_token.get('/_apis/profile/profiles/me?api-version=1.0').parsed
      end

      protected

      def build_access_token
        assertion = request.params["code"]
        client.get_token({:assertion => assertion, client_assertion => options.client_secret, :redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true)))
      end
    end
  end
end

OmniAuth.config.add_camelization 'vsts', 'VSTS'
